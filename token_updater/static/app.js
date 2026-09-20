const API = "";
const DASHBOARD_HOUR_OPTIONS = [6, 24, 72, 168];
const DASHBOARD_VIEW_OPTIONS = ["overview", "profiles", "activity"];

const state = {
    token: localStorage.getItem("t") || "",
    dashboard: null,
    refreshTimer: null,
    modal: null,
    loading: false,
    pendingRefresh: false,
    operationLock: null,
    selectedHours: normalizeDashboardHours(Number(localStorage.getItem("dashboard-hours") || 24)),
    currentView: normalizeDashboardView(localStorage.getItem("dashboard-view") || "overview"),
    stream: null,
    streamStatus: "idle",
    streamLastEventAt: 0,
    scheduledRealtimeRefresh: null,
    scheduledStreamReconnect: null,
};

const elements = {
    loginRoot: document.getElementById("login-root"),
    appRoot: document.getElementById("app-root"),
    modalRoot: document.getElementById("modal-root"),
    toastRoot: document.getElementById("toast-root"),
};

document.addEventListener("DOMContentLoaded", init);

function normalizeDashboardHours(value) {
    const hours = Number(value);
    return DASHBOARD_HOUR_OPTIONS.includes(hours) ? hours : 24;
}

function normalizeDashboardView(value) {
    return DASHBOARD_VIEW_OPTIONS.includes(String(value)) ? String(value) : "overview";
}

function bucketHoursForRange(hours) {
    if (hours <= 24) {
        return 1;
    }
    if (hours <= 72) {
        return 3;
    }
    return 6;
}

function getHourOptions(options) {
    if (Array.isArray(options) && options.length) {
        return options.map((item) => Number(item)).filter((item) => !Number.isNaN(item));
    }
    return [...DASHBOARD_HOUR_OPTIONS];
}

function getStreamStatusMeta() {
    if (state.pendingRefresh) {
        return {
            label: "有新数据待应用",
            tone: "warning",
            copy: "检测到后台更新，完成当前编辑后会自动刷新。",
        };
    }

    switch (state.streamStatus) {
        case "live":
            return {
                label: "实时已连接",
                tone: "success",
                copy: state.streamLastEventAt
                    ? `最近事件：${formatDate(new Date(state.streamLastEventAt).toISOString())}`
                    : "正在接收服务端推送。",
            };
        case "connecting":
            return {label: "实时连接中", tone: "info", copy: "正在建立 SSE 连接。"};
        case "reconnecting":
            return {label: "实时重连中", tone: "warning", copy: "连接中断，正在自动重连。"};
        case "offline":
            return {label: "轮询兜底", tone: "danger", copy: "当前未建立 SSE，系统会定时轻量刷新。"};
        default:
            return {label: "等待连接", tone: "info", copy: "登录后会自动建立实时连接。"};
    }
}

function updateStreamBadge() {
    const meta = getStreamStatusMeta();
    const pill = document.getElementById("stream-status-pill");
    const copy = document.getElementById("stream-status-copy");
    if (pill) {
        pill.className = `tag ${meta.tone}`;
        pill.textContent = meta.label;
    }
    if (copy) {
        copy.textContent = meta.copy;
    }
}

function getExecutionState() {
    if (state.operationLock?.busy) {
        return state.operationLock;
    }
    const execution = state.dashboard?.execution;
    if (execution?.busy) {
        return execution.current ? {busy: true, ...execution.current} : execution;
    }
    return {busy: false};
}

function getExecutionMessage(execution = getExecutionState()) {
    if (!execution?.busy) {
        return "浏览器相关操作会自动串行执行，执行期间相关按钮会暂时锁定。";
    }
    const label = execution.label || "任务";
    const profileName = String(execution.profile_name || "").trim();
    return profileName ? `正在执行${label}：${profileName}，其余浏览器相关操作已暂时锁定。` : `正在执行${label}，其余浏览器相关操作已暂时锁定。`;
}

function getBrowserLockAttrs() {
    const execution = getExecutionState();
    const attrs = ['data-browser-lock="true"'];
    if (execution.busy) {
        attrs.push("disabled");
        attrs.push(`title="${escapeAttr(getExecutionMessage(execution))}"`);
    }
    return attrs.join(" ");
}

function syncExecutionButtons() {
    const execution = getExecutionState();
    const message = getExecutionMessage(execution);
    document.querySelectorAll("[data-browser-lock='true']").forEach((button) => {
        const pending = button.dataset.pending === "true";
        button.disabled = execution.busy || pending;
        if (execution.busy) {
            button.title = message;
        } else {
            button.removeAttribute("title");
        }
    });
    const notice = document.getElementById("execution-lock-copy");
    if (notice) {
        notice.textContent = message;
    }
}

function setOperationLock(lockState = null) {
    state.operationLock = lockState ? {busy: true, ...lockState} : null;
    syncExecutionButtons();
}

function isInteractionLocked() {
    if (state.modal) {
        return true;
    }
    const active = document.activeElement;
    if (!active) {
        return false;
    }
    const tag = String(active.tagName || "").toUpperCase();
    return elements.appRoot.contains(active) && ["INPUT", "TEXTAREA", "SELECT"].includes(tag);
}

async function init() {
    elements.toastRoot.className = "toast-stack";

    document.addEventListener("focusout", () => {
        window.setTimeout(() => {
            if (state.pendingRefresh && !isInteractionLocked() && !state.loading && state.token) {
                refreshDashboard(true, true).catch(() => {});
            } else {
                updateStreamBadge();
            }
        }, 0);
    });

    try {
        const auth = await publicJson(`${API}/api/auth/check`);
        if (!auth.need_password) {
            showAppShell();
            await refreshDashboard(false, true);
            connectDashboardStream();
        } else if (state.token && await verifySession()) {
            showAppShell();
            await refreshDashboard(false, true);
            connectDashboardStream();
        } else {
            showLogin();
        }
    } catch (error) {
        showLogin();
        toast(error.message || "初始化失败", "error");
    }

    state.refreshTimer = window.setInterval(async () => {
        if (state.loading || elements.appRoot.classList.contains("hidden")) {
            return;
        }
        const streamHealthy = state.dashboard?.realtime?.sse_supported
            && state.streamStatus === "live"
            && Date.now() - state.streamLastEventAt < 45000;
        if (streamHealthy) {
            return;
        }
        if (isInteractionLocked()) {
            state.pendingRefresh = true;
            updateStreamBadge();
            return;
        }
        try {
            await refreshDashboard(true);
        } catch (_) {
            // 轮询兜底时静默失败。
        }
    }, 45000);

    window.addEventListener("beforeunload", () => disconnectDashboardStream(false));
}

function showLogin() {
    disconnectDashboardStream();
    closeModal(true);
    state.dashboard = null;
    state.pendingRefresh = false;
    elements.appRoot.className = "hidden";
    elements.appRoot.innerHTML = "";
    elements.loginRoot.className = "screen-center login-shell";
    elements.loginRoot.innerHTML = `
        <div class="login-card">
            <div class="login-icon">${renderIcon("lock")}</div>
            <span class="login-badge">Flow2API 控制台</span>
            <h1 class="login-title">Flow2API 控制台</h1>
            <p class="login-subtitle">请输入管理员密码以继续。</p>
            <form class="login-form" onsubmit="event.preventDefault(); doLogin(this.querySelector('button'))">
                <div class="field">
                    <label for="login-password">管理员密码</label>
                    <input id="login-password" type="password" placeholder="请输入管理员密码">
                </div>
                <button class="btn primary login-submit" type="submit">
                    登录
                    ${renderIcon("arrow-right")}
                </button>
            </form>
        </div>
    `;
    document.getElementById("login-password")?.focus();
}

function showAppShell() {
    elements.loginRoot.className = "hidden";
    elements.loginRoot.innerHTML = "";
    elements.appRoot.className = "page-shell";
}

async function verifySession() {
    try {
        const response = await request(`${API}/api/status`, {}, {allowError: true});
        return response.ok;
    } catch (_) {
        return false;
    }
}

function setStreamStatus(status) {
    state.streamStatus = status;
    updateStreamBadge();
}

function disconnectDashboardStream(resetStatus = true) {
    if (state.stream) {
        state.stream.close();
        state.stream = null;
    }
    if (state.scheduledRealtimeRefresh) {
        window.clearTimeout(state.scheduledRealtimeRefresh);
        state.scheduledRealtimeRefresh = null;
    }
    if (state.scheduledStreamReconnect) {
        window.clearTimeout(state.scheduledStreamReconnect);
        state.scheduledStreamReconnect = null;
    }
    if (resetStatus) {
        setStreamStatus("idle");
    }
}

function connectDashboardStream() {
    // Native EventSource cannot send the administrator Bearer header. Use the
    // existing polling path; never place an administrator session in a URL.
    disconnectDashboardStream(false);
    setStreamStatus("offline");
}

function scheduleRealtimeRefresh() {
    if (state.scheduledRealtimeRefresh) {
        return;
    }
    state.scheduledRealtimeRefresh = window.setTimeout(async () => {
        state.scheduledRealtimeRefresh = null;
        if (isInteractionLocked()) {
            state.pendingRefresh = true;
            updateStreamBadge();
            return;
        }
        try {
            await refreshDashboard(true);
        } catch (_) {
            // 实时刷新失败时，交给重连与轮询兜底处理。
        }
    }, 320);
}

async function refreshDashboard(silent = false, force = false) {
    if (!force && isInteractionLocked() && state.dashboard) {
        state.pendingRefresh = true;
        updateStreamBadge();
        return state.dashboard;
    }

    state.loading = true;
    try {
        state.dashboard = await fetchDashboard();
        const selectedHours = normalizeDashboardHours(state.dashboard?.filters?.hours || state.selectedHours);
        state.selectedHours = selectedHours;
        localStorage.setItem("dashboard-hours", String(selectedHours));
        state.pendingRefresh = false;
        renderApp();
        syncExecutionButtons();
        updateStreamBadge();
        return state.dashboard;
    } catch (error) {
        if (!silent && error.message !== "expired") {
            toast(error.message || "加载失败", "error");
        }
        throw error;
    } finally {
        state.loading = false;
    }
}

async function fetchDashboard() {
    const dashboardResponse = await request(`${API}/api/dashboard?hours=${state.selectedHours}`, {}, {allowError: true});
    if (dashboardResponse.ok) {
        return await safeJson(dashboardResponse);
    }
    if (dashboardResponse.status !== 404) {
        throw new Error(await parseError(dashboardResponse));
    }

    const [status, config, profiles] = await Promise.all([
        json(`${API}/api/status`),
        json(`${API}/api/config`),
        json(`${API}/api/profiles`),
    ]);
    return buildFallbackDashboard(status, config, profiles, state.selectedHours);
}

function buildFallbackDashboard(status, config, profiles, selectedHours) {
    const recentActivity = [...profiles]
        .filter((profile) => profile.last_check_time || profile.last_sync_time)
        .sort((left, right) => new Date(left.last_check_time || left.last_sync_time) - new Date(right.last_check_time || right.last_sync_time))
        .slice(-18)
        .map((profile) => {
            const lastResult = profile.last_check_result || profile.last_sync_result || "";
            return {
                profile_name: profile.name,
                message: lastResult || "暂无同步记录",
                status: getResultStatus(lastResult),
                target_url: profile.effective_flow2api_url || config.flow2api_url,
                target_label: profile.target_label || profile.effective_flow2api_url || config.flow2api_url || "未配置",
                created_at: profile.last_check_time || profile.last_sync_time,
            };
        });

    const summary = {
        total: profiles.length,
        logged_in: profiles.filter((profile) => profile.is_logged_in).length,
        active: profiles.filter((profile) => profile.is_active).length,
        custom_targets: profiles.filter((profile) => profile.flow2api_url).length,
        token_overrides: profiles.filter((profile) => profile.has_connection_token_override).length,
        proxy_enabled: profiles.filter((profile) => profile.proxy_url).length,
        window_success: recentActivity.filter((item) => item.status === "success").length,
        window_error: recentActivity.filter((item) => item.status === "error").length,
    };

    return {
        browser: status.browser,
        syncer: status.syncer,
        config,
        profiles,
        summary,
        charts: {
            sync_activity: buildSyntheticActivity(profiles, selectedHours),
            top_profiles: [...profiles]
                .sort((left, right) => (right.sync_count + right.error_count) - (left.sync_count + left.error_count))
                .slice(0, 6),
            status_breakdown: {
                active: summary.active,
                inactive: summary.total - summary.active,
                logged_in: summary.logged_in,
                not_logged_in: summary.total - summary.logged_in,
            },
            failure_reasons: buildFallbackFailureReasons(recentActivity),
            target_distribution: buildFallbackTargetDistribution(profiles, recentActivity),
        },
        recent_activity: recentActivity,
        filters: {
            hours: selectedHours,
            hour_options: getHourOptions(config.available_chart_ranges),
        },
        realtime: {
            sse_supported: false,
        },
        version: status.version || "fallback",
    };
}

function buildSyntheticActivity(profiles, hours) {
    const bucketHours = bucketHoursForRange(hours);
    const bucketCount = Math.max(1, Math.floor(hours / bucketHours));
    const now = new Date();
    now.setMinutes(0, 0, 0);
    now.setHours(now.getHours() - (now.getHours() % bucketHours));

    const buckets = [];
    const bucketMap = new Map();
    for (let index = bucketCount - 1; index >= 0; index -= 1) {
        const bucketTime = new Date(now);
        bucketTime.setHours(bucketTime.getHours() - (index * bucketHours));
        const key = bucketTime.toISOString().slice(0, 13);
        const label = hours <= 24
            ? bucketTime.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})
            : bucketTime.toLocaleString("zh-CN", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"});
        const bucket = {bucket: key, label, success: 0, error: 0};
        buckets.push(bucket);
        bucketMap.set(key, bucket);
    }

    profiles.forEach((profile) => {
        if (!profile.last_sync_time) {
            return;
        }
        const syncTime = new Date(profile.last_sync_time);
        syncTime.setMinutes(0, 0, 0);
        syncTime.setHours(syncTime.getHours() - (syncTime.getHours() % bucketHours));
        const bucket = bucketMap.get(syncTime.toISOString().slice(0, 13));
        if (!bucket) {
            return;
        }
        const resultStatus = getResultStatus(profile.last_check_result || profile.last_sync_result || "");
        if (resultStatus === "success") {
            bucket.success += 1;
        } else if (resultStatus === "error") {
            bucket.error += 1;
        }
    });

    return {bucket_hours: bucketHours, points: buckets};
}

function buildFallbackFailureReasons(events) {
    const counts = new Map();
    events.forEach((event) => {
        if (event.status !== "error") {
            return;
        }
        const label = String(event.message || "未知错误").slice(0, 28);
        counts.set(label, (counts.get(label) || 0) + 1);
    });
    return [...counts.entries()]
        .sort((left, right) => right[1] - left[1])
        .slice(0, 6)
        .map(([label, count]) => ({label, count, sample: label}));
}

function buildFallbackTargetDistribution(profiles, recentActivity) {
    const grouped = new Map();
    profiles.forEach((profile) => {
        const targetUrl = profile.effective_flow2api_url || "";
        const targetLabel = profile.target_label || targetUrl || "未配置";
        const entry = grouped.get(targetLabel) || {
            target_url: targetUrl,
            target_label: targetLabel,
            profile_count: 0,
            logged_in: 0,
            custom_count: 0,
            success: 0,
            error: 0,
        };
        entry.profile_count += 1;
        entry.logged_in += profile.is_logged_in ? 1 : 0;
        entry.custom_count += profile.flow2api_url ? 1 : 0;
        grouped.set(targetLabel, entry);
    });
    recentActivity.forEach((event) => {
        const targetLabel = event.target_label || event.target_url || "未配置";
        const entry = grouped.get(targetLabel) || {
            target_url: event.target_url || "",
            target_label: targetLabel,
            profile_count: 0,
            logged_in: 0,
            custom_count: 0,
            success: 0,
            error: 0,
        };
        if (event.status === "success") {
            entry.success += 1;
        } else if (event.status === "error") {
            entry.error += 1;
        }
        grouped.set(targetLabel, entry);
    });
    return [...grouped.values()].sort((left, right) => (right.profile_count + right.success + right.error) - (left.profile_count + left.success + left.error));
}

function getResultStatus(resultText) {
    const text = String(resultText || "").toLowerCase();
    if (text.startsWith("success")) {
        return "success";
    }
    if (text.startsWith("skipped")) {
        return "skipped";
    }
    if (text) {
        return "error";
    }
    return "info";
}

function getStatusTone(status) {
    if (status === "success") {
        return "success";
    }
    if (status === "skipped") {
        return "warning";
    }
    if (status === "error") {
        return "danger";
    }
    return "info";
}

function getStatusLabel(status) {
    if (status === "success") {
        return "成功";
    }
    if (status === "skipped") {
        return "跳过";
    }
    if (status === "error") {
        return "失败";
    }
    return "状态";
}

const ICONS = {
    lock: '<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V8a4 4 0 1 1 8 0v3"></path></svg>',
    "arrow-right": '<svg viewBox="0 0 24 24"><path d="M5 12h14"></path><path d="m13 6 6 6-6 6"></path></svg>',
    activity: '<svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"></path></svg>',
    monitor: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"></rect><path d="M8 20h8"></path><path d="M12 16v4"></path></svg>',
    refresh: '<svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-3.4-7"></path><path d="M21 3v6h-6"></path></svg>',
    logout: '<svg viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path><path d="M10 17 15 12 10 7"></path><path d="M15 12H3"></path></svg>',
    info: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"></circle><path d="M12 10v6"></path><path d="M12 7h.01"></path></svg>',
    users: '<svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2"></path><circle cx="9.5" cy="7" r="3.5"></circle><path d="M20 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a3.5 3.5 0 0 1 0 6.74"></path></svg>',
    "check-circle": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"></circle><path d="m8.5 12.5 2.3 2.3 4.7-5.3"></path></svg>',
    target: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="7"></circle><circle cx="12" cy="12" r="3"></circle><path d="M12 2v3"></path><path d="M12 19v3"></path><path d="M2 12h3"></path><path d="M19 12h3"></path></svg>',
    "trending-up": '<svg viewBox="0 0 24 24"><path d="M3 17 9 11 13 15 21 7"></path><path d="M14 7h7v7"></path></svg>',
    "trending-down": '<svg viewBox="0 0 24 24"><path d="m3 7 6 6 4-4 8 8"></path><path d="M14 17h7v-7"></path></svg>',
    server: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="2"></rect><rect x="3" y="14" width="18" height="6" rx="2"></rect><path d="M7 7h.01"></path><path d="M7 17h.01"></path></svg>',
    save: '<svg viewBox="0 0 24 24"><path d="M5 21h14V7l-4-4H5z"></path><path d="M9 21v-6h6v6"></path><path d="M9 3v4h4"></path></svg>',
    upload: '<svg viewBox="0 0 24 24"><path d="M12 16V4"></path><path d="m7 9 5-5 5 5"></path><path d="M4 20h16"></path></svg>',
    plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14"></path><path d="M5 12h14"></path></svg>',
    play: '<svg viewBox="0 0 24 24"><path d="m8 5 11 7-11 7z"></path></svg>',
    square: '<svg viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2"></rect></svg>',
    shield: '<svg viewBox="0 0 24 24"><path d="M12 3 6 6v5c0 4.5 2.9 8.6 6 10 3.1-1.4 6-5.5 6-10V6z"></path><path d="m9.5 12 1.7 1.7 3.3-3.7"></path></svg>',
    download: '<svg viewBox="0 0 24 24"><path d="M12 4v10"></path><path d="m7 10 5 5 5-5"></path><path d="M4 20h16"></path></svg>',
    cookie: '<svg viewBox="0 0 24 24"><path d="M20 13.5A6.5 6.5 0 1 1 10.5 4a3.5 3.5 0 0 0 4.5 4.5 3.5 3.5 0 0 0 4.5 5Z"></path><path d="M8.5 10h.01"></path><path d="M12 14h.01"></path><path d="M15.5 11h.01"></path></svg>',
    key: '<svg viewBox="0 0 24 24"><circle cx="7.5" cy="15.5" r="3.5"></circle><path d="M11 15.5h10"></path><path d="M18 12.5v6"></path><path d="M14.5 12.5v6"></path></svg>',
    edit: '<svg viewBox="0 0 24 24"><path d="M12 20h9"></path><path d="m16.5 3.5 4 4L8 20l-5 1 1-5z"></path></svg>',
    trash: '<svg viewBox="0 0 24 24"><path d="M3 6h18"></path><path d="M8 6V4h8v2"></path><path d="m19 6-1 14H6L5 6"></path><path d="M10 11v6"></path><path d="M14 11v6"></path></svg>',
    globe: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18"></path><path d="M12 3a15 15 0 0 1 0 18"></path><path d="M12 3a15 15 0 0 0 0 18"></path></svg>',
    clock: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path></svg>',
    "x-circle": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"></circle><path d="m9 9 6 6"></path><path d="m15 9-6 6"></path></svg>',
    x: '<svg viewBox="0 0 24 24"><path d="m6 6 12 12"></path><path d="m18 6-12 12"></path></svg>',
};

function renderIcon(name, className = "ui-icon") {
    return `<span class="${className}" aria-hidden="true">${ICONS[name] || ""}</span>`;
}

function setDashboardView(view) {
    const nextView = normalizeDashboardView(view);
    if (nextView === state.currentView) {
        return;
    }
    state.currentView = nextView;
    localStorage.setItem("dashboard-view", nextView);
    if (!state.dashboard) {
        return;
    }
    renderApp();
    syncExecutionButtons();
    updateStreamBadge();
}

function renderViewNavigation(currentView, profiles, recentActivity) {
    const items = [
        {key: "overview", label: "数据面板", count: null},
        {key: "profiles", label: "账号列表", count: profiles.length},
        {key: "activity", label: "近期动态", count: recentActivity.length},
    ];

    return `
        <nav class="view-nav" aria-label="页面导航">
            ${items.map((item) => `
                <button
                    class="view-nav-btn ${item.key === currentView ? "active" : ""}"
                    onclick="setDashboardView('${item.key}')"
                    type="button"
                >
                    <span>${escapeHtml(item.label)}</span>
                    ${item.count === null ? "" : `<span class="view-nav-count">${escapeHtml(String(item.count))}</span>`}
                </button>
            `).join("")}
        </nav>
    `;
}

function renderOverviewPanel(summary, config, targetDistribution, selectedHours) {
    return `
        <section class="stats-grid">
            ${renderMetricCard("账号总数", summary.total || 0, `${summary.active || 0} 个启用中`, "primary", "users")}
            ${renderMetricCard("已登录", summary.logged_in || 0, `未登录 ${(summary.total || 0) - (summary.logged_in || 0)} 个`, "success", "check-circle")}
            ${renderMetricCard("自定义目标", summary.custom_targets || 0, `令牌覆盖 ${summary.token_overrides || 0} 个`, "info", "target")}
            ${renderMetricCard("窗口成功", summary.window_success || 0, `最近 ${selectedHours} 小时`, "success", "trending-up")}
            ${renderMetricCard("窗口失败", summary.window_error || 0, `最近 ${selectedHours} 小时`, "danger", "trending-down")}
            ${renderMetricCard("目标实例", targetDistribution.length || summary.target_count || summary.target_instances || 0, `代理启用 ${summary.proxy_enabled || 0} 个`, "warning", "server")}
        </section>

        <section class="section-card">
            <div class="card-head">
                <div>
                    <h2 class="card-title title-with-icon">${renderIcon("target")} 默认目标配置</h2>
                </div>
            </div>
            <div class="config-grid">
                <div class="field span-2">
                    <label for="config-url">默认 Flow2API 地址</label>
                    <input id="config-url" value="${escapeAttr(config.flow2api_url || "")}" placeholder="http://host.docker.internal:8000">
                </div>
                <div class="field">
                    <label for="config-token">默认连接令牌</label>
                    <input id="config-token" type="password" placeholder="${escapeAttr(config.connection_token_preview || "留空不修改")}">
                    <span class="field-hint">留空表示保持当前默认令牌不变。</span>
                </div>
                <div class="field">
                    <label for="config-interval">刷新间隔（分钟）</label>
                    <div class="inline-field-row">
                        <input id="config-interval" type="number" min="1" max="1440" value="${escapeAttr(String(config.refresh_interval || 60))}">
                        <button class="btn primary" onclick="saveConfig(this)">${renderIcon("save")} 保存</button>
                    </div>
                </div>
            </div>
        </section>
    `;
}

function renderProfilesPanel(profiles) {
    return `
        <section class="section-card">
            <div class="card-head">
                <div>
                    <h2 class="card-title title-with-icon">${renderIcon("users")} 账号列表</h2>
                </div>
                <div class="button-row">
                    <button class="btn secondary" ${getBrowserLockAttrs()} onclick="syncAll(this)">${renderIcon("refresh")} 同步全部</button>
                    <button class="btn outline" onclick="openCredentialImportModal()">${renderIcon("upload")} 导入账号</button>
                    <button class="btn primary" onclick="openProfileModal()">${renderIcon("plus")} 新建账号</button>
                </div>
            </div>
            <div class="profiles-grid">
                ${profiles.length ? profiles.map(renderProfileCard).join("") : `
                    <div class="empty-state">
                        还没有账号。先创建账号，或点击上方“导入账号”批量导入，再通过自动登录、远程登录或导入会话数据完成登录。
                    </div>`}
            </div>
        </section>
    `;
}

function renderActivityPanel(recentActivity) {
    return `
        <section class="activity-card">
            <div class="card-head">
                <div>
                    <h2 class="card-title title-with-icon">${renderIcon("activity")} 近期动态</h2>
                </div>
                <span class="tag info">最近 ${Math.min(recentActivity.length, 18)} 条</span>
            </div>
            ${renderRecentActivity(recentActivity)}
        </section>
    `;
}

function renderApp() {
    const dashboard = state.dashboard;
    const summary = dashboard.summary || {};
    const config = dashboard.config || {};
    const charts = dashboard.charts || {};
    const browser = dashboard.browser || {};
    const profiles = dashboard.profiles || [];
    const filters = dashboard.filters || {hours: state.selectedHours, hour_options: [...DASHBOARD_HOUR_OPTIONS]};
    const targetDistribution = charts.target_distribution || [];
    const streamMeta = getStreamStatusMeta();

    const vncRunning = Boolean(browser.vnc_stack_running);
    const vncEnabled = Boolean(config.enable_vnc);
    const selectedHours = normalizeDashboardHours(filters.hours || state.selectedHours);
    const currentView = normalizeDashboardView(state.currentView);
    const execution = getExecutionState();
    const vncCopy = vncEnabled
        ? `已配置凭据的账号可直接点“自动登录”；需要人工接管时点“登录”并在远程窗口完成谷歌登录。当前 ${vncRunning ? "远程登录已可用" : "远程登录会在点击登录后按需拉起"}。`
        : "当前已禁用远程登录。已配置凭据的账号仍可尝试后台自动登录。";
    const recentActivity = dashboard.recent_activity || [];

    state.currentView = currentView;

    elements.appRoot.innerHTML = `
        <header class="topbar">
            <div class="topbar-inner">
                <div class="topbar-brand">
                    <div class="title-with-icon">
                        <span class="metric-icon primary">${renderIcon("activity")}</span>
                        <div>
                            <h1 class="hero-title">控制台 <span class="version-tag">· v${escapeHtml(dashboard.version || "-")}</span></h1>
                            <p class="hero-subtitle">账号管理、同步状态与目标配置。</p>
                        </div>
                    </div>
                </div>
                <div class="toolbar">
                    <span id="stream-status-pill" class="tag ${streamMeta.tone}">${escapeHtml(streamMeta.label)}</span>
                    <button class="btn primary" onclick="location.href='/account-import'">${renderIcon("users")} 并发导入账号</button>
                    ${vncEnabled ? `<button class="btn outline" onclick="openVnc()" ${vncRunning ? "" : "disabled"}>${renderIcon("monitor")} ${vncRunning ? "远程登录" : "远程未启动"}</button>` : ""}
                    <button class="btn ghost icon-only" onclick="refreshDashboardAction(this)" title="刷新">${renderIcon("refresh")}</button>
                    <button class="btn ghost icon-only danger-text" onclick="doLogout(this)" title="退出">${renderIcon("logout")}</button>
                </div>
            </div>
        </header>

        <main class="page-main">
            ${renderViewNavigation(currentView, profiles, recentActivity)}

            <section class="notice ${execution.busy ? "is-busy" : ""}">
                <div class="notice-icon">${renderIcon(execution.busy ? "refresh" : "info")}</div>
                <div>
                    <div class="notice-title">${execution.busy ? "任务执行中" : "运行说明"}</div>
                    <div class="notice-body-text">${escapeHtml(vncCopy)}</div>
                    <div id="stream-status-copy" class="notice-inline">${escapeHtml(streamMeta.copy)}</div>
                    <div id="execution-lock-copy" class="notice-inline">${escapeHtml(getExecutionMessage(execution))}</div>
                </div>
            </section>

            ${currentView === "overview" ? renderOverviewPanel(summary, config, targetDistribution, selectedHours) : ""}
            ${currentView === "profiles" ? renderProfilesPanel(profiles) : ""}
            ${currentView === "activity" ? renderActivityPanel(recentActivity) : ""}
        </main>
    `;
}

function renderHourFilterButtons(options, selectedHours) {
    return `
        <div class="button-row wrap-row">
            ${options.map((hours) => `
                <button class="btn ${hours === selectedHours ? "primary" : "ghost"} small" onclick="setChartRange(${hours}, this)">${hours >= 168 ? "7天" : `${hours}小时`}</button>
            `).join("")}
        </div>
    `;
}

function renderMetricCard(label, value, foot, tone = "", iconName = "") {
    return `
        <article class="metric-card ${escapeHtml(tone || "default")}">
            <div class="metric-head">
                <div class="metric-label">${escapeHtml(label)}</div>
                ${iconName ? `<span class="metric-icon ${escapeHtml(tone || "default")}">${renderIcon(iconName)}</span>` : ""}
            </div>
            <div class="metric-value ${escapeHtml(tone)}">${escapeHtml(String(value))}</div>
            <div class="metric-foot">${escapeHtml(foot || "-")}</div>
        </article>
    `;
}

function renderActivityChart(chart, selectedHours) {
    const data = chart?.points?.length ? chart.points : buildSyntheticActivity([], selectedHours).points;
    const bucketHours = Number(chart?.bucket_hours || bucketHoursForRange(selectedHours));
    const maxValue = Math.max(1, ...data.map((point) => Number(point.success || 0) + Number(point.error || 0)));
    const labelStep = data.length > 36 ? 6 : data.length > 24 ? 4 : data.length > 12 ? 2 : 1;

    return `
        <div class="chart-wrap">
            <div class="button-row wrap-row compact-row">
                <span class="tag success">成功</span>
                <span class="tag danger">失败</span>
                <span class="tag info">粒度 ${bucketHours} 小时</span>
            </div>
            <div class="activity-bars" style="grid-template-columns: repeat(${Math.max(1, data.length)}, minmax(0, 1fr));">
                ${data.map((point, index) => {
                    const total = Number(point.success || 0) + Number(point.error || 0);
                    const successHeight = Number(point.success || 0) ? Math.max(4, Math.round((Number(point.success || 0) / maxValue) * 180)) : 0;
                    const errorHeight = Number(point.error || 0) ? Math.max(4, Math.round((Number(point.error || 0) / maxValue) * 180)) : 0;
                    const label = index % labelStep === 0 ? point.label : "";
                    return `
                        <div class="activity-col" title="${escapeAttr(`${point.label} · 成功 ${point.success} / 失败 ${point.error}`)}">
                            <div class="activity-stack">
                                ${Number(point.error || 0) ? `<div class="activity-bar error" style="height:${errorHeight}px"></div>` : ""}
                                ${Number(point.success || 0) ? `<div class="activity-bar success" style="height:${successHeight}px"></div>` : total === 0 ? `<div class="activity-bar ghost-bar"></div>` : ""}
                            </div>
                            <span class="axis-label">${escapeHtml(label)}</span>
                        </div>`;
                }).join("")}
            </div>
        </div>
    `;
}

function renderStatusAndRanking(breakdown, topProfiles) {
    const loggedIn = Number(breakdown.logged_in || 0);
    const notLoggedIn = Number(breakdown.not_logged_in || 0);
    const active = Number(breakdown.active || 0);
    const inactive = Number(breakdown.inactive || 0);
    const total = Math.max(1, loggedIn + notLoggedIn);
    const ratio = Math.round((loggedIn / total) * 100);
    const donutStyle = `background: conic-gradient(var(--success) 0 ${ratio}%, rgba(148, 163, 184, 0.14) ${ratio}% 100%)`;
    const maxProfileTotal = Math.max(1, ...topProfiles.map((profile) => (profile.sync_count || 0) + (profile.error_count || 0)));

    const statusItems = [
        { label: "已登录", value: loggedIn, tone: "success" },
        { label: "未登录", value: notLoggedIn, tone: "warning" },
        { label: "启用中", value: active, tone: "primary" },
        { label: "已停用", value: inactive, tone: "danger" },
    ];

    return `
        <div class="status-ranking-shell">
            <div class="status-panel">
                <div class="donut-wrap compact-donut-wrap">
                    <div style="position:relative;">
                        <div class="donut compact-donut" style="${donutStyle}"></div>
                        <div class="donut-center">
                            <div class="donut-value">${ratio}%</div>
                            <div class="muted">登录率</div>
                        </div>
                    </div>
                </div>
                <div class="status-summary-list">
                    ${statusItems.map((item) => `
                        <div class="status-row ${item.tone}">
                            <span class="status-row-label">${item.label}</span>
                            <strong class="status-row-value">${item.value}</strong>
                        </div>
                    `).join("")}
                </div>
            </div>
            <div class="ranking-list">
                ${(topProfiles.length ? topProfiles : []).map((profile, index) => {
                    const totalOps = (profile.sync_count || 0) + (profile.error_count || 0);
                    const percent = Math.max(8, Math.round((totalOps / maxProfileTotal) * 100));
                    return `
                        <div class="ranking-row">
                            <span class="ranking-index">#${index + 1}</span>
                            <div class="ranking-body">
                                <div class="split-line">
                                    <strong>${escapeHtml(profile.name || "未命名")}</strong>
                                    <span class="mini-tag ${profile.is_logged_in ? "success" : "warning"}">${profile.is_logged_in ? "已登录" : "待登录"}</span>
                                </div>
                                <div class="progress-line ranking-progress">
                                    <div class="progress-fill" style="width:${percent}%"></div>
                                </div>
                                <div class="split-line muted ranking-meta">
                                    <span>总计 ${totalOps}</span>
                                    <span>成功 ${profile.sync_count || 0} · 失败 ${profile.error_count || 0}</span>
                                </div>
                            </div>
                        </div>`;
                }).join("") || `<div class="empty-state">暂无排行数据</div>`}
            </div>
        </div>
    `;
}

function renderLegend(label, value, tone) {
    return `
        <div class="legend-item">
            <span class="tag ${tone}">${escapeHtml(label)}</span>
            <strong>${escapeHtml(String(value || 0))}</strong>
        </div>
    `;
}

function renderFailureReasons(items) {
    if (!items.length) {
        return `<div class="empty-state">当前时间窗口内没有失败记录。</div>`;
    }

    const maxCount = Math.max(1, ...items.map((item) => Number(item.count || 0)));
    return `
        <div class="data-list">
            ${items.map((item) => {
                const width = Math.max(10, Math.round((Number(item.count || 0) / maxCount) * 100));
                return `
                    <div class="data-row">
                        <div class="split-line">
                            <strong>${escapeHtml(item.label || item.reason || "未知原因")}</strong>
                            <span class="mini-tag danger">${escapeHtml(String(item.count || 0))}</span>
                        </div>
                        <div class="progress-line subtle-progress">
                            <div class="progress-fill danger-fill" style="width:${width}%"></div>
                        </div>
                        <div class="profile-meta">${escapeHtml(item.sample || item.label || item.reason || "")}</div>
                    </div>
                `;
            }).join("")}
        </div>
    `;
}

function renderTargetDistribution(items) {
    if (!items.length) {
        return `<div class="empty-state">还没有目标实例分布数据。</div>`;
    }

    const maxProfiles = Math.max(1, ...items.map((item) => Number(item.profile_count || item.total || 0)));
    return `
        <div class="data-list">
            ${items.map((item) => {
                const totalProfiles = Number(item.profile_count || item.total || 0);
                const width = Math.max(10, Math.round((totalProfiles / maxProfiles) * 100));
                return `
                    <div class="data-row">
                        <div class="split-line">
                            <strong>${escapeHtml(item.target_label || item.label || item.target_url || "未配置")}</strong>
                            <span class="mini-tag primary">${escapeHtml(String(totalProfiles))} 个账号</span>
                        </div>
                        <div class="progress-line subtle-progress">
                            <div class="progress-fill" style="width:${width}%"></div>
                        </div>
                        <div class="split-line muted">
                            <span>已登录 ${escapeHtml(String(item.logged_in || item.logged_in_count || 0))}</span>
                            <span>成功 ${escapeHtml(String(item.success || item.success_count || 0))} / 失败 ${escapeHtml(String(item.error || item.error_count || 0))}</span>
                        </div>
                    </div>
                `;
            }).join("")}
        </div>
    `;
}

function renderProfileCard(profile) {
    const profileId = escapeJs(String(profile.id ?? ""));
    const lastResult = String(profile.last_check_result || profile.last_sync_result || "");
    const resultStatus = getResultStatus(lastResult);
    const resultTone = getStatusTone(resultStatus);
    const usesDefaultTarget = profile.uses_default_target !== false && !profile.flow2api_url;
    const targetLabel = usesDefaultTarget ? "默认目标" : "独立目标";
    const lastProcessedAt = profile.last_check_time || profile.last_sync_time;
    const profileIdentity = String(
        profile.email
        || profile.login_account
        || (profile.is_logged_in ? "已登录 / 待识别邮箱" : "未登录 / 未识别邮箱"),
    ).trim();
    const isBrowserActive = Boolean(profile.is_browser_active || profile.browser_running);
    const isActive = profile.is_active !== false && profile.is_enabled !== false;
    const hasLoginCredentials = Boolean(profile.has_login_credentials || profile.has_login_password);
    const vncEnabled = Boolean(state.dashboard?.config?.enable_vnc);
    const effectiveTarget = profile.effective_flow2api_url || profile.flow2api_url || state.dashboard?.config?.flow2api_url || "未配置";
    const successCount = profile.sync_count || profile.success_count || 0;
    const errorCount = profile.error_count || 0;

    return `
        <article class="profile-card">
            <div class="profile-top">
                <div>
                    <h3 class="profile-name">${escapeHtml(profile.name || "未命名")}</h3>
                    <div class="profile-meta-row">
                        <span class="truncate-text" title="${escapeAttr(profileIdentity)}">${escapeHtml(profileIdentity)}</span>
                        <span class="profile-dot">•</span>
                        <span class="${profile.is_logged_in ? "meta-success" : "meta-muted"}">${profile.is_logged_in ? "已登录" : "未登录"}</span>
                    </div>
                    ${profile.remark ? `<div class="profile-meta">${escapeHtml(profile.remark)}</div>` : ""}
                </div>
                <span class="badge ${isBrowserActive ? "warning" : isActive ? "success" : "default"}">
                    ${isBrowserActive ? "浏览器运行中" : isActive ? "已启用" : "已停用"}
                </span>
            </div>

            <div class="profile-tags">
                <span class="badge ${profile.is_logged_in ? "success" : "default"}">${profile.is_logged_in ? "已登录" : "未登录"}</span>
                ${profile.login_method ? `<span class="badge ${profile.login_method === "protocol" ? "info" : "primary"}">${profile.login_method === "protocol" ? "协议登录" : "浏览器登录"}</span>` : ""}
                <span class="badge ${resultTone === "info" ? "default" : resultTone} is-truncate" title="${escapeAttr(lastResult || "暂无处理结果")}">${escapeHtml(lastResult || "暂无处理结果")}</span>
                <span class="badge ${usesDefaultTarget ? "default" : "info"}">${escapeHtml(targetLabel)}</span>
                ${hasLoginCredentials ? `<span class="badge primary">已配置凭据</span>` : ""}
                ${profile.has_connection_token_override ? `<span class="badge warning">已覆盖令牌</span>` : ""}
                ${profile.proxy_url ? `<span class="badge info">代理已配置</span>` : ""}
            </div>

            <div class="profile-body">
                <div class="detail-line">
                    ${renderIcon("globe")}
                    <span class="truncate-text" title="${escapeAttr(effectiveTarget)}">${escapeHtml(effectiveTarget)}</span>
                </div>
                <div class="detail-line">
                    ${renderIcon("clock")}
                    <span>${escapeHtml(formatDate(lastProcessedAt))}</span>
                </div>
                <div class="detail-stats">
                    <span class="detail-stat success">${renderIcon("check-circle")} ${escapeHtml(String(successCount))}</span>
                    <span class="detail-stat danger">${renderIcon("x-circle")} ${escapeHtml(String(errorCount))}</span>
                </div>
            </div>

            <div class="profile-footer">
                <div class="button-row wrap-row">
                    ${!isBrowserActive && hasLoginCredentials
                        ? `<button class="btn primary small" ${getBrowserLockAttrs()} onclick="autoLogin('${profileId}', this)">${renderIcon("play")} 自动登录</button>`
                        : ""}
                    ${vncEnabled
                        ? (isBrowserActive
                            ? `<button class="btn danger small" ${getBrowserLockAttrs()} onclick="closeBrowser('${profileId}', this)">${renderIcon("square")} 关闭浏览器</button>`
                            : `<button class="btn secondary small" ${getBrowserLockAttrs()} onclick="launchBrowser('${profileId}', this)">${renderIcon("monitor")} 登录</button>`)
                        : ""}
                    <button class="btn outline small" ${getBrowserLockAttrs()} onclick="checkLogin('${profileId}', this)">${renderIcon("shield")} 检测</button>
                    <button class="btn outline small" ${getBrowserLockAttrs()} onclick="syncProfile('${profileId}', this)">${renderIcon("refresh")} 同步</button>
                    <button class="btn outline small" onclick="openCookieModal('${profileId}')">${renderIcon("cookie")} 会话数据</button>
                    <button class="btn outline small" onclick="openProtocolLoginModal('${profileId}')">${renderIcon("key")} 协议登录</button>
                </div>
                <div class="button-row end-row">
                    <button class="btn ghost small" onclick="openProfileModal('${profileId}')">${renderIcon("edit")} 编辑</button>
                    <button class="btn ghost small danger-text" ${getBrowserLockAttrs()} onclick="deleteProfile('${profileId}', '${escapeJs(profile.name || "")}', this)">${renderIcon("trash")} 删除</button>
                </div>
            </div>
        </article>
    `;
}

function renderRecentActivity(events) {
    if (!events.length) {
        return `<div class="empty-state">还没有同步记录，先手动同步一次看看。</div>`;
    }

    return `
        <div class="activity-list">
            ${events.map((event) => `
                <div class="activity-item">
                    <div class="activity-main">
                        <span class="badge ${getStatusTone(event.status)} activity-badge">${escapeHtml(getStatusLabel(event.status))}</span>
                        <div class="activity-copy">
                            <div class="activity-line">
                                <strong>${escapeHtml(event.profile_name || "系统")}</strong>
                                <span>${escapeHtml(event.message || event.action || "暂无说明")}</span>
                                ${event.reason_category ? `<span class="mini-tag info">${escapeHtml(event.reason_category)}</span>` : ""}
                            </div>
                            <div class="activity-meta">${escapeHtml(event.target_label || event.target_url || "未记录目标地址")}</div>
                        </div>
                    </div>
                    <div class="activity-time">${escapeHtml(formatDate(event.created_at))}</div>
                </div>`).join("")}
        </div>
    `;
}

async function setChartRange(hours, button) {
    const nextHours = normalizeDashboardHours(hours);
    if (nextHours === state.selectedHours && state.dashboard) {
        return;
    }

    state.selectedHours = nextHours;
    localStorage.setItem("dashboard-hours", String(nextHours));
    await withButton(button, "切换中...", async () => {
        await refreshDashboard(false, true);
    });
}

async function doLogin(button) {
    const password = (document.getElementById("login-password")?.value || "").trim();
    if (!password) {
        toast("请输入管理员密码", "error");
        return;
    }

    await withButton(button, "登录中...", async () => {
        const response = await publicRequest(`${API}/api/login`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({password}),
        }, {allowError: true});
        const data = await safeJson(response);
        if (!response.ok || !data.success) {
            throw new Error(data.detail || data.error || "密码错误");
        }
        state.token = data.token;
        localStorage.setItem("t", data.token);
        showAppShell();
        await refreshDashboard(false, true);
        toast("登录成功", "success");
    });
}

async function doLogout(button) {
    await withButton(button, "退出中...", async () => {
        try {
            await request(`${API}/api/logout`, {method: "POST"}, {allowError: true});
        } catch (_) {
            // 忽略退出时的网络抖动。
        }
        handleExpiredSession();
        toast("已退出", "success");
    });
}

async function refreshDashboardAction(button) {
    await withButton(button, "刷新中...", async () => {
        await refreshDashboard(false, true);
        toast("已刷新", "success");
    });
}

async function saveConfig(button) {
    const url = (document.getElementById("config-url")?.value || "").trim();
    const connectionToken = document.getElementById("config-token")?.value || "";
    const intervalValue = (document.getElementById("config-interval")?.value || "").trim();

    if (!url) {
        toast("请输入默认 Flow2API 地址", "error");
        return;
    }

    const refreshInterval = Number(intervalValue || 60);
    if (!Number.isInteger(refreshInterval) || refreshInterval < 1 || refreshInterval > 1440) {
        toast("刷新间隔需在 1-1440 分钟之间", "error");
        return;
    }

    const payload = {flow2api_url: url, refresh_interval: refreshInterval};
    if (connectionToken) {
        payload.connection_token = connectionToken;
    }

    await withButton(button, "保存中...", async () => {
        await json(`${API}/api/config`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload),
        });
        await refreshDashboard(false, true);
        document.getElementById("config-token").value = "";
        toast("默认配置已保存", "success");
    });
}

function openProfileModal(profileId = null) {
    if (profileId) {
        loadProfileModal(profileId);
        return;
    }
    renderProfileModal({is_active: true, proxy_enabled: false}, false);
}

async function loadProfileModal(profileId) {
    try {
        const profile = await json(`${API}/api/profiles/${profileId}`);
        renderProfileModal(profile, true);
    } catch (error) {
        toast(error.message || "读取账号失败", "error");
    }
}

function renderProfileModal(profile, editing) {
    state.modal = {type: "profile", profileId: profile.id || null, editing};
    const hasOverride = Boolean(profile.connection_token_override || profile.connection_token_override_preview);
    const hasLoginCredentials = Boolean(profile.has_login_credentials || profile.has_login_password);
    showModal(`
        <div class="modal-card modal-wide">
            <div class="modal-head">
                <div>
                    <span class="eyebrow">${editing ? "编辑账号" : "新建账号"}</span>
                    <h3 class="modal-title">${editing ? "编辑账号" : "新建账号"}</h3>
                    <p class="modal-copy">${editing ? "调整账号登录、代理和目标配置。" : "创建一个新的 Flow2API 账号。"}</p>
                </div>
                <button class="btn ghost icon-only" onclick="closeModal()" title="关闭">${renderIcon("x")}</button>
            </div>
            <div class="form-grid">
                <div class="field span-2">
                    <label for="profile-name">账号名称</label>
                    <input id="profile-name" value="${escapeAttr(profile.name || "")}" placeholder="例如：主账号-A">
                </div>
                <div class="field span-2">
                    <label for="profile-remark">备注</label>
                    <input id="profile-remark" value="${escapeAttr(profile.remark || "")}" placeholder="写点备注，后面找起来更快">
                </div>
                <div class="field">
                    <label for="profile-login-account">登录账号</label>
                    <input id="profile-login-account" value="${escapeAttr(profile.login_account || "")}" placeholder="邮箱、手机号或 Workspace 账号">
                </div>
                <div class="field">
                    <label for="profile-login-password">登录密码</label>
                    <input id="profile-login-password" type="password" placeholder="${escapeAttr(hasLoginCredentials ? "已保存，留空则不修改" : "留空则不配置自动登录")}">
                    <span class="field-hint">保存后会用于账号卡片里的自动登录。</span>
                </div>
                <div class="field span-2">
                    <label>启用状态</label>
                    <label class="switch">
                        <input id="profile-active" type="checkbox" ${profile.is_active === false ? "" : "checked"}>
                        <span>该账号参与自动同步</span>
                    </label>
                </div>
                <div class="field">
                    <label for="profile-proxy">源浏览器代理地址</label>
                    <input id="profile-proxy" value="${escapeAttr(profile.proxy_url || "")}" placeholder="http://user:pass@host:port">
                    <span class="field-hint">留空表示不走代理。</span>
                </div>
                <div class="field">
                    <label for="profile-target-url">Flow2API 地址覆盖</label>
                    <input id="profile-target-url" value="${escapeAttr(profile.flow2api_url || "")}" placeholder="留空则使用全局默认地址">
                    <span class="field-hint">适合把某个账号单独推到另一套 Flow2API。</span>
                </div>
                <div class="field">
                    <label for="profile-captcha-proxy">目标 Flow2API 代理地址</label>
                    <input id="profile-captcha-proxy" value="${escapeAttr(profile.captcha_proxy_url || "")}" placeholder="首次同步或授权续期时需填写目标可访问的同出口代理">
                    <span class="field-hint">填写目标服务器可访问、与源浏览器同出口的代理地址。</span>
                </div>
                <div class="field">
                    <label for="profile-target-token">连接令牌覆盖</label>
                    <input id="profile-target-token" type="password" placeholder="${escapeAttr(profile.connection_token_override_preview || "留空则使用全局默认令牌")}">
                    <span class="field-hint">输入新值会覆盖；留空默认不修改当前值。</span>
                </div>
            </div>
            ${hasOverride ? `
                <div class="field span-2">
                    <label class="switch">
                        <input id="profile-clear-token-override" type="checkbox">
                        <span>清空当前连接令牌覆盖，改回使用全局默认值</span>
                    </label>
                </div>` : ""}
            ${editing && hasLoginCredentials ? `
                <div class="field span-2">
                    <label class="switch">
                        <input id="profile-clear-login-credentials" type="checkbox">
                        <span>清空当前登录账号和登录密码，关闭自动登录</span>
                    </label>
                </div>` : ""}
            <div class="modal-actions">
                <button class="btn outline" onclick="closeModal()">取消</button>
                <button class="btn primary" onclick="saveProfile(this)">${editing ? "保存变更" : "创建账号"}</button>
            </div>
        </div>
    `);
}

async function saveProfile(button) {
    const modal = state.modal || {};
    const name = (document.getElementById("profile-name")?.value || "").trim();
    const remark = (document.getElementById("profile-remark")?.value || "").trim();
    const loginAccount = (document.getElementById("profile-login-account")?.value || "").trim();
    const loginPassword = document.getElementById("profile-login-password")?.value || "";
    const clearLoginCredentials = Boolean(document.getElementById("profile-clear-login-credentials")?.checked);
    const proxyUrl = (document.getElementById("profile-proxy")?.value || "").trim();
    const flow2apiUrl = (document.getElementById("profile-target-url")?.value || "").trim();
    const tokenOverride = document.getElementById("profile-target-token")?.value || "";
    const clearOverride = Boolean(document.getElementById("profile-clear-token-override")?.checked);
    const isActive = Boolean(document.getElementById("profile-active")?.checked);

    if (!name) {
        toast("请输入账号名称", "error");
        return;
    }

    const payload = {
        name,
        remark,
        is_active: isActive,
        login_account: loginAccount,
        proxy_url: proxyUrl,
        captcha_proxy_url: (document.getElementById("profile-captcha-proxy")?.value || "").trim(),
        flow2api_url: flow2apiUrl,
    };
    if (!modal.editing || loginPassword) {
        payload.login_password = loginPassword;
    }
    if (modal.editing && clearLoginCredentials) {
        payload.clear_login_credentials = true;
    }
    if (!modal.editing || tokenOverride) {
        payload.connection_token_override = tokenOverride;
    }
    if (modal.editing && clearOverride) {
        payload.connection_token_override = "";
    }

    await withButton(button, modal.editing ? "保存中..." : "创建中...", async () => {
        if (modal.editing) {
            await json(`${API}/api/profiles/${modal.profileId}`, {
                method: "PUT",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(payload),
            });
        } else {
            await json(`${API}/api/profiles`, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(payload),
            });
        }
        closeModal();
        await refreshDashboard(false, true);
        toast(modal.editing ? "账号已保存" : "账号已创建", "success");
    });
}

function openCredentialImportModal() {
    state.modal = {type: "import-accounts"};
    showModal(`
        <div class="modal-card modal-compact">
            <div class="modal-head">
                <div>
                    <span class="eyebrow">导入账号密码</span>
                    <h3 class="modal-title">批量导入自动登录凭据</h3>
                    <p class="modal-copy">按行粘贴账号文本，系统会自动解析并导入。</p>
                </div>
                <button class="btn ghost icon-only" onclick="closeModal()" title="关闭">${renderIcon("x")}</button>
            </div>
            <div class="info-panel">
                <div class="info-panel-head">
                    ${renderIcon("info")}
                    <strong>支持格式</strong>
                </div>
                <ul class="info-list">
                    <li>三列：名称,账号,密码，支持逗号、Tab、|、---- 分隔。</li>
                    <li>两列：账号,密码，名称会自动使用账号。</li>
                </ul>
            </div>
            <div class="field">
                <label for="accounts-import-content">账号文本</label>
                <textarea id="accounts-import-content" placeholder="名称,账号,密码&#10;备用号,foo@gmail.com,pass123&#10;&#10;也支持两列：账号,密码"></textarea>
            </div>
            <div class="field">
                <label class="switch">
                    <input id="accounts-import-update-existing" type="checkbox" checked>
                    <span>名称重复时更新已有账号的登录凭据</span>
                </label>
            </div>
            <div class="modal-actions">
                <button class="btn outline" onclick="closeModal()">取消</button>
                <button class="btn primary" onclick="submitCredentialImport(this)">开始导入</button>
            </div>
        </div>
    `);
}

async function submitCredentialImport(button) {
    const content = (document.getElementById("accounts-import-content")?.value || "").trim();
    const updateExisting = Boolean(document.getElementById("accounts-import-update-existing")?.checked);
    if (!content) {
        toast("请输入要导入的账号文本", "error");
        return;
    }

    await withButton(button, "导入中...", async () => {
        const result = await json(`${API}/api/profiles/import-accounts`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({content, update_existing: updateExisting}),
        });
        closeModal(true);
        await refreshDashboard(false, true);
        toast(`导入完成：新增 ${result.created || 0}，更新 ${result.updated || 0}，跳过 ${result.skipped || 0}`, "success");
    });
}

function openCookieModal(profileId) {
    const profile = (state.dashboard?.profiles || []).find((item) => String(item.id) === String(profileId)) || {};
    state.modal = {type: "cookie", profileId};
    showModal(`
        <div class="modal-card modal-compact">
            <div class="modal-head">
                <div>
                    <span class="eyebrow">会话数据管理</span>
                    <h3 class="modal-title">导入或导出当前登录态</h3>
                    <p class="modal-copy">为 <strong>${escapeHtml(profile.name || "当前账号")}</strong> 导入 Cookie JSON 后，系统会写入持久化浏览器资料并自动刷新 session。也可以直接导出当前账号的 labs.google Cookie 作为备份。</p>
                </div>
                <button class="btn ghost icon-only" onclick="closeModal()" title="关闭">${renderIcon("x")}</button>
            </div>
            <div class="field">
                <label for="cookie-json">会话数据文本</label>
                <textarea id="cookie-json" placeholder='[{"name":"...","value":"...","domain":".labs.google","path":"/","secure":true}]'></textarea>
            </div>
            <div class="modal-actions">
                <button class="btn outline" onclick="closeModal()">取消</button>
                <button class="btn secondary" ${getBrowserLockAttrs()} onclick="exportCookies(this, 'session')">${renderIcon("download")} 导出当前会话</button>
                <button class="btn primary" ${getBrowserLockAttrs()} onclick="submitCookies(this)">导入会话数据</button>
            </div>
        </div>
    `);
}

function openProtocolLoginModal(profileId) {
    const profile = (state.dashboard?.profiles || []).find((item) => String(item.id) === String(profileId)) || {};
    state.modal = {type: "protocol-login", profileId};
    showModal(`
        <div class="modal-card modal-compact">
            <div class="modal-head">
                <div>
                    <span class="eyebrow">协议 Cookie 管理</span>
                    <h3 class="modal-title">导入或导出 Google Cookies</h3>
                    <p class="modal-copy">为 <strong>${escapeHtml(profile.name || "当前账号")}</strong> 刷新 Labs 授权，再通过源浏览器校验完整 Flow 会话。也可以导出当前账号已保存的 Google Cookies 进行备份或迁移。</p>
                </div>
                <button class="btn ghost icon-only" onclick="closeModal()" title="关闭">${renderIcon("x")}</button>
            </div>
            <div class="field">
                <label for="google-cookies">Google Cookies</label>
                <textarea id="google-cookies" placeholder='粘贴保留 domain、path、expires 的 Cookie JSON 数组，包含 Google 主域登录 Cookie 和 flow.google.com 的 OSID。'></textarea>
                <span class="field-hint">合并导出 <strong>.google.com</strong>、<strong>accounts.google.com</strong>、<strong>flow.google.com</strong> 的完整 Cookie JSON，保留域名和有效期。只有 Labs session 或旧版纯文本 Cookie 不代表 Flow 已登录；需要二次验证时请使用手动登录。</span>
            </div>
            <div class="modal-actions">
                <button class="btn outline" onclick="closeModal()">取消</button>
                <button class="btn secondary" onclick="exportCookies(this, 'google')">${renderIcon("download")} 导出当前 Google Cookies</button>
                <button class="btn primary" ${getBrowserLockAttrs()} onclick="submitProtocolLogin(this)">协议登录</button>
            </div>
        </div>
    `);
}

async function submitCookies(button) {
    const modal = state.modal || {};
    const cookiesJson = (document.getElementById("cookie-json")?.value || "").trim();
    if (!cookiesJson) {
        toast("请输入会话数据文本", "error");
        return;
    }

    await withOperationLock(button, "导入中...", {action: "import_cookies", label: "导入会话数据"}, async () => {
        const data = await json(`${API}/api/profiles/${modal.profileId}/import-cookies`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({cookies_json: cookiesJson}),
        });
        closeModal(true);
        await refreshDashboard(false, true);
        toast(data.has_token ? "导入成功，已检测到会话令牌" : "已导入，但暂未检测到会话令牌", data.has_token ? "success" : "error");
    });
}

async function exportCookies(button, kind = "google") {
    const modal = state.modal || {};
    const textareaId = kind === "google" ? "google-cookies" : "cookie-json";

    await withOperationLock(button, "导出中...", {action: "export_cookies", label: "导出 Cookie", profile_id: modal.profileId}, async () => {
        const data = await json(`${API}/api/profiles/${modal.profileId}/export-cookies?kind=${encodeURIComponent(kind)}`);
        const formatted = String(data.cookies_json || "");
        if (!formatted) {
            throw new Error("未获取到可导出的 Cookie 内容");
        }
        const textarea = document.getElementById(textareaId);
        if (textarea) {
            textarea.value = formatted;
        }
        const filename = data.filename || `profile-${modal.profileId}-${kind}-cookies.json`;
        downloadTextFile(filename, formatted);
        const count = Number(data.cookie_count ?? data.count ?? 0);
        const successMessage = kind === "google"
            ? `已导出 ${count} 条 Google Cookie`
            : (data.has_token ? `已导出 ${count} 条 Cookie，包含会话令牌` : `已导出 ${count} 条 Cookie`);
        toast(successMessage, "success");
    });
}

async function submitProtocolLogin(button) {
    const modal = state.modal || {};
    const googleCookies = (document.getElementById("google-cookies")?.value || "").trim();
    if (!googleCookies) {
        toast("请输入 Google Cookies", "error");
        return;
    }

    await withOperationLock(button, "登录中...", {action: "protocol_login", label: "协议登录", profile_id: modal.profileId}, async () => {
        const data = await json(`${API}/api/profiles/${modal.profileId}/protocol-login`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({google_cookies: googleCookies}),
        });
        closeModal(true);
        await refreshDashboard(false, true);
        toast(data.success ? "协议登录成功，已获取会话令牌" : (data.error || "协议登录失败"), data.success ? "success" : "error");
    });
}

async function syncAll(button) {
    await withOperationLock(button, "同步中...", {action: "sync_all", label: "同步全部账号"}, async () => {
        const result = await json(`${API}/api/sync-all`, {method: "POST"});
        await refreshDashboard(false, true);
        toast(`已完成：成功 ${result.success_count || 0}，失败 ${result.error_count || 0}，跳过 ${result.skipped || 0}`, "success");
    });
}

async function syncProfile(profileId, button) {
    await withOperationLock(button, "同步中...", {action: "sync_profile", label: "同步账号", profile_id: profileId}, async () => {
        const result = await json(`${API}/api/profiles/${profileId}/sync`, {method: "POST"});
        await refreshDashboard(false, true);
        toast(result.success ? "同步成功" : result.error || "同步失败", result.success ? "success" : "error");
    });
}

async function checkLogin(profileId, button) {
    await withOperationLock(button, "检测中...", {action: "check_login", label: "检测登录状态", profile_id: profileId}, async () => {
        const result = await json(`${API}/api/profiles/${profileId}/check-login`, {method: "POST"});
        await refreshDashboard(false, true);
        toast(result.is_logged_in ? "已登录" : "未登录或已过期", result.is_logged_in ? "success" : "error");
    });
}

async function autoLogin(profileId, button) {
    await withOperationLock(button, "登录中...", {action: "auto_login", label: "自动登录", profile_id: profileId}, async () => {
        const result = await json(`${API}/api/profiles/${profileId}/auto-login`, {method: "POST"});
        await refreshDashboard(false, true);
        toast(result.has_token ? "自动登录成功，已获取会话令牌" : "自动登录成功", "success");
    });
}

async function launchBrowser(profileId, button) {
    await withOperationLock(button, "启动中...", {action: "launch_browser", label: "启动浏览器登录", profile_id: profileId}, async () => {
        await json(`${API}/api/profiles/${profileId}/launch`, {method: "POST"});
        await waitVncReady();
        await refreshDashboard(false, true);
        openVnc();
        toast("浏览器已启动，请在远程登录窗口完成登录", "success");
    });
}

async function closeBrowser(profileId, button) {
    await withOperationLock(button, "关闭中...", {action: "close_browser", label: "关闭浏览器", profile_id: profileId}, async () => {
        const result = await json(`${API}/api/profiles/${profileId}/close`, {method: "POST"});
        await refreshDashboard(false, true);
        toast(result.is_logged_in ? "浏览器已关闭，登录状态已保存" : "浏览器已关闭", "success");
    });
}

async function deleteProfile(profileId, profileName, button) {
    if (!window.confirm(`确认删除 "${profileName}" 吗？`)) {
        return;
    }

    await withOperationLock(button, "删除中...", {action: "delete_profile", label: "删除账号", profile_id: profileId, profile_name: profileName}, async () => {
        await request(`${API}/api/profiles/${profileId}`, {method: "DELETE"});
        await refreshDashboard(false, true);
        toast("账号已删除", "success");
    });
}
async function waitVncReady(timeoutMs = 10000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            const status = await json(`${API}/api/status`);
            if (status?.browser?.vnc_stack_running) {
                return true;
            }
        } catch (_) {
            // 轮询等待即可。
        }
        await delay(500);
    }
    return false;
}

function openVnc() {
    const url = `${location.protocol}//${location.hostname}:6080/vnc.html`;
    window.open(url, "_blank", "noopener");
}

function showModal(content) {
    elements.modalRoot.className = "modal-layer";
    elements.modalRoot.innerHTML = content;
}

function closeModal(skipRefresh = false) {
    state.modal = null;
    elements.modalRoot.className = "hidden";
    elements.modalRoot.innerHTML = "";
    if (!skipRefresh && state.pendingRefresh && !state.loading && state.token) {
        refreshDashboard(true, true).catch(() => {});
    } else {
        updateStreamBadge();
    }
}

elements.modalRoot.addEventListener("click", (event) => {
    if (event.target === elements.modalRoot) {
        closeModal();
    }
});

function toast(message, type = "success") {
    const toastElement = document.createElement("div");
    toastElement.className = `toast ${type}`;
    toastElement.textContent = message;
    elements.toastRoot.appendChild(toastElement);
    window.setTimeout(() => toastElement.remove(), 3200);
}

async function withOperationLock(button, pendingText, lockState, action) {
    setOperationLock(lockState);
    try {
        await withButton(button, pendingText, action);
    } finally {
        setOperationLock(null);
    }
}

async function withButton(button, pendingText, action) {
    const original = button ? button.innerHTML : "";
    if (button) {
        button.dataset.pending = "true";
        button.disabled = true;
        button.innerHTML = pendingText;
    }
    try {
        await action();
    } catch (error) {
        if (error.message !== "expired") {
            toast(error.message || "操作失败", "error");
        }
    } finally {
        if (button) {
            delete button.dataset.pending;
            button.disabled = false;
            button.innerHTML = original;
        }
        syncExecutionButtons();
    }
}

async function request(url, options = {}, {allowError = false, auth = true} = {}) {
    const headers = new Headers(options.headers || {});
    if (auth && state.token) {
        headers.set("X-Flow-Updater-Authorization", `Bearer ${state.token}`);
    }

    const response = await fetch(url, {...options, headers});
    if (auth && response.status === 401) {
        handleExpiredSession();
        throw new Error("expired");
    }
    if (!allowError && !response.ok) {
        throw new Error(await parseError(response));
    }
    return response;
}

async function publicRequest(url, options = {}, {allowError = false} = {}) {
    const response = await fetch(url, options);
    if (!allowError && !response.ok) {
        throw new Error(await parseError(response));
    }
    return response;
}

async function json(url, options = {}, requestOptions = {}) {
    const response = await request(url, options, requestOptions);
    return safeJson(response);
}

async function publicJson(url, options = {}) {
    const response = await publicRequest(url, options);
    return safeJson(response);
}

async function safeJson(response) {
    try {
        return await response.json();
    } catch (_) {
        return {};
    }
}

async function parseError(response) {
    const data = await safeJson(response);
    return data.detail || data.error || data.message || `请求失败（状态码 ${response.status}）`;
}

function handleExpiredSession() {
    disconnectDashboardStream();
    state.token = "";
    localStorage.removeItem("t");
    showLogin();
}

function delay(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function downloadTextFile(filename, content) {
    const blob = new Blob([content], {type: "application/json;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function formatDate(value) {
    if (!value) {
        return "暂无记录";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }
    return date.toLocaleString("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function escapeAttr(value) {
    return escapeHtml(value).replace(/`/g, "&#96;");
}

function escapeJs(value) {
    return String(value ?? "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

window.doLogin = doLogin;
window.doLogout = doLogout;
window.refreshDashboardAction = refreshDashboardAction;
window.setDashboardView = setDashboardView;
window.setChartRange = setChartRange;
window.saveConfig = saveConfig;
window.openProfileModal = openProfileModal;
window.saveProfile = saveProfile;
window.closeModal = closeModal;
window.openCredentialImportModal = openCredentialImportModal;
window.submitCredentialImport = submitCredentialImport;
window.openCookieModal = openCookieModal;
window.openProtocolLoginModal = openProtocolLoginModal;
window.submitCookies = submitCookies;
window.exportCookies = exportCookies;
window.submitProtocolLogin = submitProtocolLogin;
window.syncAll = syncAll;
window.syncProfile = syncProfile;
window.checkLogin = checkLogin;
window.autoLogin = autoLogin;
window.launchBrowser = launchBrowser;
window.closeBrowser = closeBrowser;
window.deleteProfile = deleteProfile;
window.openVnc = openVnc;
