from uuid import uuid4

def generate_vc_id() -> str:
    return f"vc-{uuid4().hex}"
