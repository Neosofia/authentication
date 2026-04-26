async function testMeEndpoint() {
  const btn = document.getElementById("test-api-btn");
  const out = document.getElementById("api-response");

  btn.disabled = true;
  out.className = "response-display";
  out.innerHTML = "<em>Fetching token…</em>";

  try {
    // Step 1: exchange session cookie for a platform JWT
    const tokenResp = await fetch("/api/token", {
      method: "POST",
      credentials: "include",
    });

    if (!tokenResp.ok) {
      const err = await tokenResp.json().catch(() => ({}));
      throw new Error(`/api/token ${tokenResp.status}: ${err.error || tokenResp.statusText}`);
    }

    const { access_token } = await tokenResp.json();

    // Step 2: call /api/me with the JWT
    const meResp = await fetch("/api/me", {
      headers: { Authorization: `Bearer ${access_token}` },
      credentials: "include",
    });

    const body = await meResp.json();

    out.className = "response-display " + (meResp.ok ? "success" : "error");
    out.innerHTML =
      `<strong>HTTP ${meResp.status}</strong><pre class="response-pre">${JSON.stringify(body, null, 2)}</pre>`;
  } catch (e) {
    out.className = "response-display error";
    out.innerHTML = `<strong>Error:</strong> ${e.message}`;
  } finally {
    btn.disabled = false;
  }
}

async function testMachineToken() {
  const btn = document.getElementById("machine-token-btn");
  const out = document.getElementById("machine-token-response");
  const clientId = document.getElementById("machine-client-id").value;
  const clientSecret = document.getElementById("machine-client-secret").value;

  btn.disabled = true;
  out.className = "response-display";
  out.innerHTML = "<em>Requesting token…</em>";

  try {
    const resp = await fetch("/api/token", {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });

    const data = await resp.json().catch(() => ({}));

    out.className = "response-display " + (resp.ok ? "success" : "error");
    out.innerHTML =
      `<strong>HTTP ${resp.status}</strong><pre class="response-pre">${JSON.stringify(data, null, 2)}</pre>`;
  } catch (e) {
    out.className = "response-display error";
    out.innerHTML = `<strong>Error:</strong> ${e.message}`;
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", function () {
  const testBtn = document.getElementById("test-api-btn");
  if (testBtn) testBtn.addEventListener("click", testMeEndpoint);

  const machineBtn = document.getElementById("machine-token-btn");
  if (machineBtn) machineBtn.addEventListener("click", testMachineToken);
});

