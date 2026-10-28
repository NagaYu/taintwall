"""Offline in-memory mock tools; no method connects to an external service."""

from dataclasses import dataclass, field


@dataclass
class MockTools:
    outbox: list[dict[str, str]] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    http_posts: list[dict[str, str]] = field(default_factory=list)
    memory: list[str] = field(default_factory=list)
    purchases: list[dict[str, str | float]] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    def send_email(self, to: str, body: str) -> str:
        self.outbox.append({"kind": "email", "to": to, "body": body})
        return f"Mock email sent to {to}."

    def http_post(self, url: str, body: str) -> str:
        self.http_posts.append({"url": url, "body": body})
        return f"Mock HTTP POST recorded for {url}."

    def send_message(self, to: str, body: str) -> str:
        self.outbox.append({"kind": "message", "to": to, "body": body})
        return f"Mock message sent to {to}."

    def read_file(self, path: str) -> str:
        self.reads.append(path)
        if path not in self.files:
            return f"Mock file not found: {path}."
        return self.files[path]

    def write_file(self, path: str, content: str) -> str:
        self.files[path] = content
        return f"Mock file written: {path}."

    def delete_file(self, path: str) -> str:
        existed = path in self.files
        self.files.pop(path, None)
        return f"Mock file {'deleted' if existed else 'not found'}: {path}."

    def purchase(self, item: str, amount: str | float) -> str:
        self.purchases.append({"item": item, "amount": amount})
        return f"Mock purchase recorded: {item}."

    def exec(self, command: str) -> str:
        self.commands.append(command)
        return "Mock command recorded; it was not executed."

    def memory_save(self, content: str) -> str:
        self.memory.append(content)
        return "Mock memory entry saved."
