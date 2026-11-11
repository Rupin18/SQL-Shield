
const REFRESH_INTERVAL = 5000;

function updateText(id, value) {
    const element = document.getElementById(id);

    if (element && value !== undefined && value !== null) {
        element.textContent = value;
    }
}

function renderEvents(events) {
    const container = document.getElementById("event-list");
    if (!container) return;

    container.replaceChildren();

    if (!Array.isArray(events) || events.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";

        const icon = document.createElement("span");
        icon.textContent = "◉";

        const message = document.createElement("p");
        message.textContent = "No security events recorded yet.";

        const note = document.createElement("small");
        note.textContent = "Events will appear here when available.";

        empty.append(icon, message, note);
        container.appendChild(empty);
        return;
    }

    events.forEach(event => {
        const item = document.createElement("div");
        item.className = "event-item";

        const indicator = document.createElement("span");
        indicator.className = "event-indicator";

        const content = document.createElement("div");
        content.className = "event-content";

        const title = document.createElement("strong");
        title.textContent = event.title || event.event_type || "Security event";

        const description = document.createElement("small");
        description.textContent = event.description || "";

        const time = document.createElement("span");
        time.className = "event-time";
        time.textContent = event.time || event.created_at || "";

        content.append(title, description);
        item.append(indicator, content, time);
        container.appendChild(item);
    });
}

function renderActivity(activity) {
    const container = document.getElementById("activity-chart");
    if (!container) return;

    container.replaceChildren();

    if (!Array.isArray(activity) || activity.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";

        const icon = document.createElement("span");
        icon.textContent = "▥";

        const message = document.createElement("p");
        message.textContent = "No scan activity recorded yet.";

        const note = document.createElement("small");
        note.textContent = "Run a security assessment to populate this chart.";

        empty.append(icon, message, note);
        container.appendChild(empty);
        return;
    }

    const chart = document.createElement("div");
    chart.className = "activity-bars";

    const maxValue = Math.max(
        1,
        ...activity.map(item => Number(item.total) || 0)
    );

    activity.forEach((item, index) => {
        const column = document.createElement("div");
        column.className = "activity-column";

        const count = document.createElement("strong");
        count.className = "bar-count";
        count.textContent = item.total ?? 0;

        const track = document.createElement("div");
        track.className = "bar-track";

        const bar = document.createElement("div");
        bar.className = "activity-bar";

        bar.style.height =
            `${Math.max(4, ((Number(item.total) || 0) / maxValue) * 100)}%`;

        bar.style.animationDelay = `${index * 0.08}s`;

        const label = document.createElement("small");
        label.textContent = item.scan_date || item.day || "";

        track.appendChild(bar);
        column.append(count, track, label);
        chart.appendChild(column);
    });

    container.appendChild(chart);
}

function updateDashboard(data) {
    const stats = data.stats || {};
    const severity = data.severity || {};

    updateText("total-scans", stats.total_scans);
    updateText("total-vulnerabilities", stats.total_vulnerabilities);
    updateText("blocked-inputs", stats.blocked_inputs);

    updateText(
        "security-score",
        stats.security_score == null
            ? "--%"
            : `${stats.security_score}%`
    );

    updateText("critical-count", severity.critical);
    updateText("high-count", severity.high);
    updateText("medium-count", severity.medium);
    updateText("low-count", severity.low);

    renderEvents(data.events || []);
    renderActivity(data.activity || []);
}

async function loadDashboard() {
    const dashboardElements = [
        "total-scans",
        "total-vulnerabilities",
        "blocked-inputs",
        "security-score",
        "critical-count",
        "high-count",
        "medium-count",
        "low-count",
        "event-list",
        "activity-chart"
    ];

    const needsDashboard = dashboardElements.some(id =>
        document.getElementById(id)
    );

    if (!needsDashboard) return;

    try {
        const response = await fetch("/api/dashboard", {
            method: "GET",
            headers: {
                "Accept": "application/json"
            },
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`Dashboard API returned ${response.status}`);
        }

        const data = await response.json();
        updateDashboard(data);

    } catch (error) {
        console.error("Dashboard update failed:", error);
    }
}

// SQL Injection Detection Form
const detectionForm = document.getElementById("detection-form");

if (detectionForm) {
    detectionForm.addEventListener("submit", async event => {
        event.preventDefault();

        const input = document.getElementById("sql-input");
        const button = document.getElementById("detect-button");
        const result = document.getElementById("detection-result");

        if (!input || !button || !result) return;

        if (!input.value.trim()) {
            result.hidden = false;
            result.className = "detection-result danger-result";
            result.textContent = "Please enter input to analyze.";
            return;
        }

        button.disabled = true;
        button.textContent = "Analyzing...";

        result.hidden = false;
        result.className = "detection-result";
        result.textContent = "Analyzing submitted input...";

        try {
            const response = await fetch("/api/detect", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    input: input.value.trim()
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "Detection request failed.");
            }

            result.className = "detection-result " +
                (data.detected ? "danger-result" : "safe-result");

            result.textContent =
                (data.message || "Analysis completed.") +
                (data.action ? " " + data.action : "");

            if (data.success !== false) {
                await loadDashboard();
            }

        } catch (error) {
            result.className = "detection-result danger-result";
            result.textContent =
                error.message || "Unable to contact the detection service.";

            console.error("Detection error:", error);

        } finally {
            button.disabled = false;
            button.textContent = "Analyze Input →";
        }
    });
}

// SQL Injection Mitigation Test
const mitigationForm = document.getElementById("mitigation-form");

if (mitigationForm) {
    mitigationForm.addEventListener("submit", async event => {
        event.preventDefault();

        const username = document.getElementById("username-test");
        const button = document.getElementById("mitigation-button");
        const result = document.getElementById("mitigation-result");

        if (!username || !button || !result) return;

        if (!username.value.trim()) {
            result.hidden = false;
            result.className = "detection-result danger-result";
            result.textContent = "Please enter a username.";
            return;
        }

        button.disabled = true;
        button.textContent = "Testing...";

        result.hidden = false;
        result.className = "detection-result";
        result.textContent = "Testing parameterized query...";

        try {
            const response = await fetch("/api/mitigation-test", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    username: username.value.trim()
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "Mitigation request failed.");
            }

            result.className =
                "detection-result " +
                (data.protected ? "safe-result" : "danger-result");

            result.textContent = data.message || "Mitigation test completed.";

        } catch (error) {
            result.className = "detection-result danger-result";
            result.textContent =
                error.message || "Unable to contact the mitigation service.";

            console.error("Mitigation test error:", error);

        } finally {
            button.disabled = false;
            button.textContent = "Test Secure Query →";
        }
    });
}

// Initialize and refresh dashboard data only when required.
document.addEventListener("DOMContentLoaded", () => {
    loadDashboard();
    setInterval(loadDashboard, REFRESH_INTERVAL);
});
