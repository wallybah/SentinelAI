const { spawn } = require("child_process");
const path = require("path");

const root = __dirname;
const python = path.join(root, ".venv", "Scripts", "python.exe");

const processes = [];

function startProcess(name, args, cwd = root) {
    console.log(`Starting ${name}...`);

    const proc = spawn(python, args, {
        cwd,
        stdio: "inherit",
        windowsHide: false
    });

    processes.push({ name, proc });

    proc.on("error", (err) => {
        console.error(`${name} error:`, err.message);
    });

    proc.on("exit", (code) => {
        console.log(`${name} stopped with code ${code}`);
    });

    return proc;
}

// Main SentinelAI backend
startProcess("Backend", [
    "-m", "uvicorn",
    "backend.main:app",
    "--host", "127.0.0.1",
    "--port", "8000"
]);

// AI Assistant backend
startProcess("AI Assistant", [
    "-m", "uvicorn",
    "backend.assistant:app",
    "--host", "127.0.0.1",
    "--port", "8001"
]);

// Frontend
startProcess("Frontend", [
    "-m", "http.server",
    "5500"
], path.join(root, "frontend"));

console.log("");
console.log("========================================");
console.log("        SentinelAI is starting...");
console.log("========================================");
console.log("Backend:      http://127.0.0.1:8000");
console.log("AI Assistant: http://127.0.0.1:8001");
console.log("Frontend:     http://127.0.0.1:5500");
console.log("========================================");
console.log("");

// Give the frontend a few seconds to start, then open it
setTimeout(() => {
    spawn("cmd", ["/c", "start", "http://127.0.0.1:5500"], {
        detached: true,
        stdio: "ignore"
    });
}, 3000);

// Stop all services when Ctrl+C is pressed
function shutdown() {
    console.log("\nStopping SentinelAI...");

    for (const { proc } of processes) {
        if (proc && !proc.killed) {
            try {
                spawn("taskkill", ["/pid", proc.pid, "/T", "/F"]);
            } catch (err) {
                // Ignore shutdown errors
            }
        }
    }

    setTimeout(() => process.exit(0), 1000);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
