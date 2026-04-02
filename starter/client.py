import json
import secrets
import socket

from dh_utils import derive_key_material, public_component, shared_secret, xor_bytes

HOST = "127.0.0.1"
PORT = 5050


def json_write(w, obj: dict) -> None:
    w.write(json.dumps(obj, ensure_ascii=False) + "\n")
    w.flush()


def json_read(r) -> dict:
    line = r.readline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.strip())


def is_valid_student_name(student_name: str) -> bool:
    """
    TODO(student, YOUR CODE HERE):
    Strengthen validation.
    Required by lab:
    - at least 2 characters
    - letters only (space and hyphen allowed)
    - must NOT contain ';' or '='
    """
    if len(student_name) < 2:
        return False
    if ";" in student_name or "=" in student_name:
        return False
    for ch in student_name:
        if ch.isalpha() or ch in {" ", "-"}:
            continue
        return False
    return True


def ask_student_name() -> str:
    """Require student name to be entered before sending data."""
    while True:
        student_name = input("Введите ваше имя (латиница/кириллица): ").strip()
        if is_valid_student_name(student_name):
            return student_name
        print("[client] Некорректное имя, попробуйте снова.")


def ask_nonempty(prompt: str) -> str:
    """Ask for non-empty metadata field."""
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("[client] Поле не должно быть пустым.")


def main() -> None:
    p = 7919
    g = 2

    a = secrets.randbelow(p - 2) + 2
    A = public_component(g, a, p)
    student_name = ask_student_name()
    student_group = ask_nonempty("Введите вашу группу: ")
    student_number = ask_nonempty("Введите ваш номер (в журнале/списке): ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        r = sock.makefile("r", encoding="utf-8")
        w = sock.makefile("w", encoding="utf-8")

        json_write(w, {"p": p, "g": g, "A": A})
        server_reply = json_read(r)
        B = int(server_reply["B"])

        K_client = shared_secret(B, a, p)
        key = derive_key_material(K_client, length=32)
        print(f"[client] shared K = {K_client}")
        print("[client] Режим чата: вводите сообщения; пустая строка или quit — выход.")
       
        #TODO
        first_msg = (
            f"student_name={student_name}; "
            f"student_group={student_group}; "
            f"student_number={student_number}; "
            f"message=Hello from client (encrypted)."
        ).encode("utf-8")

        json_write(w, {"ciphertext_hex": xor_bytes(first_msg, key).hex()})
        enc_response = json_read(r)
        response_pt = xor_bytes(
            bytes.fromhex(enc_response["ciphertext_hex"]), key
        )
        
        #TODO
        print(f"[client] decrypted server response: {response_pt.decode('utf-8')}")

        while True:
            text = input("[client] сообщение> ").strip()
            if not text or text.lower() == "quit":
                json_write(w, {"action": "bye"})
                print("[client] отправлено завершение сеанса (bye)")
                break
            pt = text.encode("utf-8")
            json_write(w, {"ciphertext_hex": xor_bytes(pt, key).hex()})
            reply = json_read(r)
            out = xor_bytes(bytes.fromhex(reply["ciphertext_hex"]), key)
            print(f"[client] ответ сервера: {out.decode('utf-8')}")


if __name__ == "__main__":
    main()
