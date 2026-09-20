const title = document.getElementById("title");
const instructions = document.getElementById("instructions");
const status = document.getElementById("status");
const frame = document.getElementById("vnc");
const done = document.getElementById("done");
let waitingForCheck = false;

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

done.addEventListener("click", async () => {
  done.disabled = true;
  try {
    await json("/login-slots/complete", {method: "POST"});
    waitingForCheck = true;
    status.textContent = " 已通知管理员；请保留本页。检查通过后桌面会关闭，需补授权时可在同一桌面继续。";
  } catch (error) {
    done.disabled = false;
    status.textContent = ` ${error.message}`;
  }
});
setInterval(async () => {
  if (!waitingForCheck) return;
  try {
    const session = await json("/login-slots/session");
    if (session.state === "ready") {
      waitingForCheck = false;
      done.disabled = false;
      status.textContent = " 检查尚未通过，请在同一桌面完成缺少的 Flow/Labs 步骤后再次提交。";
    }
  } catch (_) {
    waitingForCheck = false;
    frame.remove();
    status.textContent = " 登录桌面已由管理员关闭；请等待后续串行验收。";
  }
}, 5000);
init().catch(error => {
  title.textContent = error.message;
  status.textContent = " 请联系管理员重新生成邀请。";
});
