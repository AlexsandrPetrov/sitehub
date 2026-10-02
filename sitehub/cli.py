"""Recovery / maintenance CLI:  sitehub <command> ...

  create-admin <login> [password]   create an administrator (random password if omitted)
  passwd <login> [password]         reset a user's password
  disable-2fa <login>               turn off two-factor auth for a user
  unban [ip|--all]                  remove IP bans
  set-port <port>                   change the listening port
  ssl-off                           switch back to plain HTTP
  users                             list users
  show                              print current settings
After changing port/SSL run: systemctl restart sitehub
"""
import sys

from . import config, db, security


def _user(login: str):
    u = db.q1("SELECT * FROM users WHERE username=?", (login,))
    if not u:
        sys.exit(f"Пользователь {login} не найден")
    return u


def main(argv: list[str]) -> None:
    db.init()
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd, args = argv[0], argv[1:]
    if cmd == "create-admin" and args:
        pw = args[1] if len(args) > 1 else security.generate_password()
        if db.q1("SELECT id FROM users WHERE username=?", (args[0],)):
            sys.exit("Такой пользователь уже существует (используйте passwd)")
        db.ex("INSERT INTO users(username,password,role,stamp,created_at) VALUES(?,?,?,?,?)",
              (args[0], security.hash_password(pw), "admin", security.new_stamp(), db.now()))
        db.audit("user_created", "cli", None, f"{args[0]} (admin)")
        print(f"Администратор создан: {args[0]} / {pw}")
    elif cmd == "passwd" and args:
        u = _user(args[0])
        pw = args[1] if len(args) > 1 else security.generate_password()
        db.ex("UPDATE users SET password=?, stamp=?, active=1 WHERE id=?",
              (security.hash_password(pw), security.new_stamp(), u["id"]))
        db.audit("password_reset", "cli", None, u["username"])
        print(f"Новый пароль для {u['username']}: {pw}")
    elif cmd == "disable-2fa" and args:
        u = _user(args[0])
        db.ex("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last=0, recovery=NULL WHERE id=?", (u["id"],))
        db.audit("2fa_reset", "cli", None, u["username"])
        print(f"2FA для {u['username']} отключена")
    elif cmd == "unban":
        if not args or args[0] == "--all":
            db.ex("DELETE FROM bans")
            db.ex("UPDATE login_attempts SET success=-1 WHERE success=0")
        else:
            db.ex("DELETE FROM bans WHERE ip=?", (args[0],))
            db.ex("UPDATE login_attempts SET success=-1 WHERE success=0 AND ip=?", (args[0],))
        print("Блокировки сняты")
    elif cmd == "set-port" and args and args[0].isdigit() and 0 < int(args[0]) < 65536:
        config.set_many({"port": args[0]})
        print(f"Порт: {args[0]}. Выполните: systemctl restart sitehub")
    elif cmd == "ssl-off":
        config.set_many({"ssl_mode": "off"})
        print("HTTPS отключён. Выполните: systemctl restart sitehub")
    elif cmd == "users":
        for u in db.q("SELECT * FROM users ORDER BY username"):
            print(f"{u['username']:24} {u['role']:7} {'active' if u['active'] else 'DISABLED':8} "
                  f"2fa={'on' if u['totp_enabled'] else 'off'}")
    elif cmd == "show":
        for k, v in sorted(config.all_settings().items()):
            print(f"{k:20} = {v}")
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
