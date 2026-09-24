const title = document.getElementById("title");
const instructions = document.getElementById("instructions");
const status = document.getElementById("status");
const frame = document.getElementById("vnc");

async function json(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {"Content-Type": "application/json", ...(options.headers || {})},
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "邀请无效或已过期");
  return data;
}

async function init() {
  let session;
  const capability = decodeURIComponent(location.hash.slice(1));
  if (capability) {
    history.replaceState(null, "", "/login-slots");
    session = await json("/login-slots/claim", {
      method: "POST", body: JSON.stringify({capability}),
    });
  } else {
    session = await json("/login-slots/session");
  }
  title.textContent = `独立登录槽位 ${session.slot}`;
  instructions.classList.remove("hidden");
  frame.src = `/login-slots/vnc/vnc.html?autoconnect=1&resize=scale&path=${encodeURIComponent(`login-slots/vnc/websockify?slot=${session.slot}`)}`;
  frame.classList.remove("hidden");
}

setInterval(async () => {
  try {
    const session = await json("/login-slots/session");
    status.textContent = session.state === "checking"
      ? " 管理员正在执行无成本检查，请暂时不要操作。"
      : " 完成可见授权后保持本页打开；管理员会直接检查。";
  } catch (_) {
    frame.remove();
    status.textContent = " 登录桌面已由管理员关闭；请等待后续串行验收。";
  }
}, 5000);
init().catch(error => {
  title.textContent = error.message;
  status.textContent = " 请联系管理员重新生成邀请。";
});
