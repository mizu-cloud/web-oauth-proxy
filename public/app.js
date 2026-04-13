const state = {
  sites: []
};

const elements = {
  adminName: document.getElementById("adminName"),
  siteList: document.getElementById("siteList"),
  form: document.getElementById("siteForm"),
  flash: document.getElementById("flash"),
  formTitle: document.getElementById("formTitle"),
  resetButton: document.getElementById("resetButton"),
  siteId: document.getElementById("siteId"),
  displayName: document.getElementById("displayName"),
  host: document.getElementById("host"),
  upstreamUrl: document.getElementById("upstreamUrl"),
  issuer: document.getElementById("issuer"),
  clientId: document.getElementById("clientId"),
  clientSecret: document.getElementById("clientSecret"),
  scopes: document.getElementById("scopes"),
  redirectPath: document.getElementById("redirectPath"),
  postLogoutRedirectUrl: document.getElementById("postLogoutRedirectUrl"),
  enabled: document.getElementById("enabled")
};

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  if (response.status === 204) {
    return null;
  }

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Request failed.");
  }

  return payload;
}

async function loadAdmin() {
  const payload = await request("/api/me");
  elements.adminName.textContent = payload.user.name;
}

async function loadSites() {
  const payload = await request("/api/sites");
  state.sites = payload.sites;
  renderSites();
}

function setFlash(message, isError = false) {
  elements.flash.textContent = message;
  elements.flash.className = isError ? "flash error" : "flash";
}

function resetForm() {
  elements.form.reset();
  elements.siteId.value = "";
  elements.enabled.checked = true;
  elements.redirectPath.value = "/_auth/callback";
  elements.scopes.value = "openid profile email";
  elements.formTitle.textContent = "Create new host";
  setFlash("");
}

function toPayload() {
  return {
    displayName: elements.displayName.value,
    host: elements.host.value,
    upstreamUrl: elements.upstreamUrl.value,
    issuer: elements.issuer.value,
    clientId: elements.clientId.value,
    clientSecret: elements.clientSecret.value,
    scopes: elements.scopes.value,
    redirectPath: elements.redirectPath.value,
    postLogoutRedirectUrl: elements.postLogoutRedirectUrl.value,
    enabled: elements.enabled.checked
  };
}

function fillForm(site) {
  elements.siteId.value = site.id;
  elements.displayName.value = site.displayName;
  elements.host.value = site.host;
  elements.upstreamUrl.value = site.upstreamUrl;
  elements.issuer.value = site.oidc.issuer;
  elements.clientId.value = site.oidc.clientId;
  elements.clientSecret.value = "";
  elements.scopes.value = site.oidc.scopes;
  elements.redirectPath.value = site.oidc.redirectPath;
  elements.postLogoutRedirectUrl.value = site.oidc.postLogoutRedirectUrl || "";
  elements.enabled.checked = site.enabled;
  elements.formTitle.textContent = `Edit ${site.host}`;
}

function renderSites() {
  if (state.sites.length === 0) {
    elements.siteList.innerHTML = "<p>No sites configured yet.</p>";
    return;
  }

  elements.siteList.innerHTML = state.sites
    .map(
      (site) => `
        <article class="site-card">
          <h3>${escapeHtml(site.displayName)}</h3>
          <p><strong>${escapeHtml(site.host)}</strong></p>
          <p>Upstream: ${escapeHtml(site.upstreamUrl)}</p>
          <p>Issuer: ${escapeHtml(site.oidc.issuer)}</p>
          <p>Scopes: ${escapeHtml(site.oidc.scopes)}</p>
          <span class="badge ${site.enabled ? "" : "off"}">${site.enabled ? "Enabled" : "Disabled"}</span>
          <div class="site-actions">
            <button data-action="edit" data-id="${site.id}" class="ghost">Edit</button>
            <button data-action="toggle" data-id="${site.id}" class="ghost">${site.enabled ? "Disable" : "Enable"}</button>
            <button data-action="delete" data-id="${site.id}" class="ghost">Delete</button>
          </div>
        </article>
      `
    )
    .join("");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setFlash("Saving...");

  try {
    const id = elements.siteId.value;
    const method = id ? "PUT" : "POST";
    const url = id ? `/api/sites/${id}` : "/api/sites";
    await request(url, {
      method,
      body: JSON.stringify(toPayload())
    });
    await loadSites();
    resetForm();
    setFlash("Site saved.");
  } catch (error) {
    setFlash(error.message, true);
  }
});

elements.resetButton.addEventListener("click", () => {
  resetForm();
});

elements.siteList.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) {
    return;
  }

  const site = state.sites.find((item) => String(item.id) === button.dataset.id);
  if (!site) {
    return;
  }

  try {
    if (button.dataset.action === "edit") {
      fillForm(site);
      return;
    }

    if (button.dataset.action === "toggle") {
      await request(`/api/sites/${site.id}/toggle`, { method: "POST" });
      await loadSites();
      setFlash("Site status updated.");
      return;
    }

    if (button.dataset.action === "delete") {
      await request(`/api/sites/${site.id}`, { method: "DELETE" });
      await loadSites();
      resetForm();
      setFlash("Site deleted.");
    }
  } catch (error) {
    setFlash(error.message, true);
  }
});

Promise.all([loadAdmin(), loadSites()]).catch((error) => {
  setFlash(error.message, true);
});
