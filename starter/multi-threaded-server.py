import json
import os
import secrets
import socket
import threading

from dh_utils import derive_key_material, public_component, shared_secret, xor_bytes

HOST = "127.0.0.1"
PORT = int(os.getenv("PORT", "5000"))


def json_write(w, obj: dict) -> None:
    w.write(json.dumps(obj, ensure_ascii=False) + "\n")
    w.flush()


def json_read(r) -> dict:
    line = r.readline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.strip())


def extract_field(plaintext: str, key: str) -> str:
    marker = f"{key}="
    if marker not in plaintext:
        return ""
    return plaintext.split(marker, 1)[1].split(";", 1)[0].strip()


def log(addr, message: str) -> None:
    print(f"[server {addr} {threading.current_thread().name}] {message}")


def handle_client(conn: socket.socket, addr) -> None:
    with conn:
        log(addr, "connected")
        r = conn.makefile("r", encoding="utf-8")
        w = conn.makefile("w", encoding="utf-8")

        try:
            hello = json_read(r)
            p = int(hello["p"])
            g = int(hello["g"])
            A = int(hello["A"])

            b = secrets.randbelow(p - 2) + 2
            B = public_component(g, b, p)
            json_write(w, {"B": B})

            K_server = shared_secret(A, b, p)
            key = derive_key_material(K_server, length=32)
            log(addr, f"shared K = {K_server}")

            first_done = False

            while True:
                try:
                    payload = json_read(r)
                except EOFError:
                    log(addr, "client closed connection")
                    break

                if payload.get("action") == "bye":
                    log(addr, "client ended session (bye)")
                    break

                if "ciphertext_hex" not in payload:
                    log(addr, "ERROR: expected ciphertext_hex or action=bye")
                    break

                ct = bytes.fromhex(payload["ciphertext_hex"])
                plaintext = xor_bytes(ct, key).decode("utf-8")
                log(addr, f"decrypted: {plaintext}")

                if not first_done:
                    first_done = True
                    student_name = extract_field(plaintext, "student_name")
                    student_group = extract_field(plaintext, "student_group")
                    student_number = extract_field(plaintext, "student_number")

                    if not all([student_name, student_group, student_number]):
                        response = (
                            "ERROR: invalid first message "
                            "(need student_name, student_group, student_number)."
                        ).encode("utf-8")
                        json_write(w, {"ciphertext_hex": xor_bytes(response, key).hex()})
                        log(addr, "error response sent, closing connection")
                        break

                    log(
                        addr,
                        "student metadata: "
                        f"name={student_name}, group={student_group}, number={student_number}",
                    )
                    response = (
                        f"Hello, {student_name} (group {student_group}, number {student_number}). "
                        "Server received your encrypted message. "
                        "Send more messages or empty line / quit on client to exit."
                    ).encode("utf-8")
                else:
                    response = f"ECHO: {plaintext}".encode("utf-8")

                json_write(w, {"ciphertext_hex": xor_bytes(response, key).hex()})
                log(addr, "response sent")
        finally:
            r.close()
            w.close()
            log(addr, "connection closed")


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[server] listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            print(f"[server] new connection from {addr}")
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()


if __name__ == "__main__":
    main()
