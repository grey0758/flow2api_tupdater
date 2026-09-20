const token = localStorage.getItem("t") || "";
const auth = {"Authorization": `Bearer ${token}`, "Content-Type": "application/json"};
const profileSelect = document.getElementById("profile");
const toast = document.getElementById("toast");

async function request(path, options = {}) {
  const response = await fetch(path, {...options, headers: {...auth, ...(options.headers || {})}});
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    location.href = "/";
    throw new Error("请先登录管理员控制台");
  }
  if (!response.ok) throw new Error(data.detail || "操作失败");
  return data;
}

function show(message, error = false) {
  toast.textContent = message;
  toast.style.color = error ? "#b42318" : "#18743e";
}

async function refresh() {
  const [slotData, profiles] = await Promise.all([
    request("/api/login-slots"),
    request("/api/profiles"),
  ]);
  document.getElementById("slots").innerHTML = slotData.slots.map(slot =>
    `<div class="slot ${slot.state === "free" ? "" : "busy"}"><strong>槽位 ${slot.slot}</strong><br>
    ${slot.state === "free" ? "空闲" : `Profile #${slot.profile_id} · ${slot.state}`}</div>`
  ).join("");
  const candidates = profiles.filter(item =>
    item.login_slot_prepared && !item.is_active && !item.is_browser_active
    && Number(item.sync_count || 0) === 0
    && !item.has_google_cookies && !item.has_login_credentials && !item.login_slot_claimed
  );
  profileSelect.replaceChildren();
  for (const item of candidates) {
    const option = document.createElement("option");
    option.value = String(item.id);
    option.textContent = `${item.name} (#${item.id})`;
    profileSelect.append(option);
  }
  if (!candidates.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "暂无符合条件的 Profile";
    profileSelect.append(option);
  }
  document.getElementById("start").disabled = !candidates.length
    || slotData.slots.every(slot => slot.state !== "free");
}

document.getElementById("prepare").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const result = await request("/api/login-slots/prepare", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("name").value,
        source_proxy_url: document.getElementById("source-proxy").value,
        captcha_proxy_url: document.getElementById("captcha-proxy").value,
      }),
    });
    document.getElementById("prepare-result").textContent =
      `Profile #${result.profile_id} 已创建且保持 inactive。`;
    await refresh();
  } catch (error) { show(error.message, true); }
});

document.getElementById("start").addEventListener("click", async () => {
  try {
    const id = Number(profileSelect.value);
    const result = await request(`/api/login-slots/${id}/start`, {method: "POST"});
    const url = new URL(result.invite_url, location.href).href;
    document.getElementById("invite-url").value = url;
    document.getElementById("invite").classList.remove("hidden");
    show(`槽位 ${result.slot} 已启动；邀请链接不会提供同步或 Cookie 导出功能。`);
    await refresh();
  } catch (error) { show(error.message, true); }
});

document.getElementById("copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(document.getElementById("invite-url").value);
  show("邀请链接已复制。");
});
document.getElementById("refresh").addEventListener("click", () => refresh().catch(error => show(error.message, true)));
refresh().catch(error => show(error.message, true));
