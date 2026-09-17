import { spawn } from "node:child_process";
import { platform } from "node:os";

/**
 * Best-effort: open a URL in the user's default browser. Never throws — a
 * headless host or missing opener just means the caller's surfaced link is
 * the fallback. Detached and unref'd so the opener cannot keep the process
 * alive.
 */
export function openInBrowser(url: string): void {
  // `url` carries attacker-influenced query params (the authorize URL
  // includes caller-supplied scopes/params). `cmd /c start` on win32 is a
  // shell command line that re-splits its argument on `&`, so a scope or
  // state value containing `&` would be reinterpreted as a second command;
  // `rundll32 url.dll,FileProtocolHandler <url>` is a real executable
  // invoked via argv, never a shell, on every platform here.
  const command =
    platform() === "darwin"
      ? "open"
      : platform() === "win32"
        ? "rundll32"
        : "xdg-open";
  const args =
    platform() === "win32" ? ["url.dll,FileProtocolHandler", url] : [url];
  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.on("error", () => undefined);
    child.unref();
  } catch {
    // Opening the browser is a convenience; the copyable link is the fallback.
  }
}
