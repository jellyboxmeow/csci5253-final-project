#!/usr/bin/env python3

from concurrent import futures
import logging
import uuid

import orchestrator.postgresql.db as db
import orchestrator.orchestrator as orchestrator
import grpc
import gRPC.gRPC_api_pb2 as gRPC_api_pb2
import gRPC.gRPC_api_pb2_grpc as gRPC_api_pb2_grpc
from google.protobuf import json_format
from grpc_reflection.v1alpha import reflection

log = logging.getLogger("server")
workers = futures.ThreadPoolExecutor(max_workers=4)   # background pipeline workers

OUTPUT_ONLY = ("status", "status_reason", "pipeline_state", "severity", "score", "findings", "action_taken")

def row_to_email(row) -> "gRPC_api_pb2.email":
    msg = gRPC_api_pb2.email()
    json_format.ParseDict(row["email"], msg, ignore_unknown_fields=True)
    msg.message_id = row["message_id"]
    msg.pipeline_state = row["state"]
    msg.severity = row["severity"] or ""
    msg.score = row["score"] or 0
    msg.findings.extend(row["findings"] or [])
    msg.action_taken = row["action_taken"] or ""
    if row["severity"] == "low":
        msg.status = gRPC_api_pb2.EMAIL_STATUS_GOOD
    elif row["severity"] in ("medium", "high"):
        msg.status = gRPC_api_pb2.EMAIL_STATUS_BAD
    else:
        msg.status = gRPC_api_pb2.EMAIL_STATUS_UNSPECIFIED
    if row["error"]:
        msg.status_reason = row["error"]
    elif row["findings"]:
        msg.status_reason = "; ".join(row["findings"][:3])
    else:
        msg.status_reason = row["state"]
    return msg

class gRPCServicer(gRPC_api_pb2_grpc.GRPCAPIServicer):
    """Implementation methods"""

    def analyzeEmail(self, request, context):
        email_to_verify = request.email_to_analyze
        if not email_to_verify or not ():
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Email needs a sender and a body")
        for field in OUTPUT_ONLY:
            email_to_verify.ClearField(field)
        email_id = uuid.uuid4().hex
        email_to_verify.message_id = email_id

        email_entry = json_format.MessageToDict(email_to_verify, preserving_proto_field_name=True)
        db.insert_email(email_id, email_entry)
        workers.submit(orchestrator.process, email_id, email_entry)
        log.info("[%s] received from %s", email_id, email_to_verify.sender)
        
        response = gRPC_api_pb2.analyzeReply()
        response.analyzed_email = row_to_email(db.get_email(email_id))
        return response
    
    def listEmails(self, request, context):
        size = min(request.list_size or 20, 100)
        token = request.list_token
        if token and not token.isdigit():
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Bad list_token")
        rows = db.list_emails(int(token or 0), size)
        response = gRPC_api_pb2.listReply(emails=[row_to_email(r) for r in rows])
        if len(rows) == size:
            response.next_list_token = str(rows[-1]["id"])
        return response

    def getSeverity(self, request, context):
        row = db.get_email(request.message_id)
        if row is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "Unknown message_id")
        if row["severity"]:
            return gRPC_api_pb2.severityReply(severity=row["severity"])
        return gRPC_api_pb2.severityReply(severity="FAILED" if row["state"] == "FAILED" else "PENDING")

def serve():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    db.init_db()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    gRPC_api_pb2_grpc.add_GRPCAPIServicer_to_server(gRPCServicer(), server)
    SERVICE_NAMES = (
        gRPC_api_pb2.DESCRIPTOR.services_by_name['GRPCAPI'].full_name,
        reflection.SERVICE_NAME
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)
    
    server.add_insecure_port("[::]:5000")
    server.start()
    print('Starting server. Listening on port 5000.')
    server.wait_for_termination()

if __name__ == "__main__":
    serve()