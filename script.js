/**
 * InvoEase Pro – Freelance Invoice & OWASP Top 10 Testing Suite
 * Frontend Controller & State Management
 */

// Application State
const state = {
  currentUser: null,
  token: localStorage.getItem('invoease_token') || '',
  securityMode: 'lab',
  invoices: [],
  clients: [],
  items: [
    { desc: 'Full-Stack Web App Development', qty: 1, price: 45000 },
    { desc: 'UI/UX Interactive Prototyping', qty: 1, price: 12000 }
  ],
  currentLogoUrl: '',
  activeStatusFilter: '',
  matrix: []
};

// ==========================================
// 1. INITIALIZATION & SETUP
// ==========================================
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupThemeToggle();
  setupAuthModal();
  setupInvoiceGenerator();
  setupOwaspDrawer();

  // Load initial mode and auth check
  await fetchSecurityMode();
  await checkAuthStatus();
  await loadDashboardData();
  await loadOwaspMatrix();
});

// Helper for authenticated fetch
async function apiFetch(url, options = {}) {
  const headers = options.headers || {};
  if (state.token) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }
  if (!headers['Content-Type'] && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }
  options.headers = headers;
  options.credentials = 'include';
  return fetch(url, options);
}

// ==========================================
// 2. THEME & NAVIGATION
// ==========================================
function setupThemeToggle() {
  const toggleBtn = document.getElementById('themeToggleBtn');
  const savedTheme = localStorage.getItem('invoease_theme') || 'dark';

  if (savedTheme === 'light') {
    document.body.classList.remove('dark-theme');
    document.body.classList.add('light-theme');
    toggleBtn.textContent = '☀️';
  } else {
    document.body.classList.add('dark-theme');
    document.body.classList.remove('light-theme');
    toggleBtn.textContent = '🌙';
  }

  toggleBtn.onclick = () => {
    if (document.body.classList.contains('dark-theme')) {
      document.body.classList.replace('dark-theme', 'light-theme');
      toggleBtn.textContent = '☀️';
      localStorage.setItem('invoease_theme', 'light');
    } else {
      document.body.classList.replace('light-theme', 'dark-theme');
      toggleBtn.textContent = '🌙';
      localStorage.setItem('invoease_theme', 'dark');
    }
  };
}

function setupNavigation() {
  const navButtons = document.querySelectorAll('.nav-btn');
  navButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const viewTarget = btn.getAttribute('data-view');
      switchView(viewTarget);
    });
  });

  document.getElementById('createNewInvoiceBtn').onclick = () => switchView('generator');
  document.getElementById('closeBannerBtn').onclick = () => {
    document.getElementById('globalBanner').classList.add('hidden');
  };
}

function switchView(viewName) {
  document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
  const activeBtn = document.querySelector(`.nav-btn[data-view="${viewName}"]`);
  if (activeBtn) activeBtn.classList.add('active');

  document.querySelectorAll('.view-section').forEach((sec) => sec.classList.remove('active'));
  const targetSec = document.getElementById(`view-${viewName}`);
  if (targetSec) targetSec.classList.add('active');

  // Load contextual data
  if (viewName === 'dashboard') loadDashboardData();
  if (viewName === 'clients') loadClientsData();
  if (viewName === 'logs') loadAuditLogs();
}

// ==========================================
// 3. SECURITY MODE CONTROLLER
// ==========================================
async function fetchSecurityMode() {
  try {
    const res = await fetch('/api/security/mode');
    const data = await res.json();
    state.securityMode = data.mode || 'lab';
    updateSecurityModeUI();
  } catch (e) {
    console.error('Error fetching security mode:', e);
  }
}

function updateSecurityModeUI() {
  const badge = document.getElementById('securityModeBadge');
  const text = document.getElementById('securityModeText');
  const banner = document.getElementById('globalBanner');
  const bannerMsg = document.getElementById('bannerMessage');
  const drawerMode = document.getElementById('drawerCurrentModeText');

  if (state.securityMode === 'lab') {
    badge.className = 'mode-pill lab-mode';
    text.textContent = '🧪 LAB MODE: Auditable';
    banner.className = 'global-banner lab-banner';
    bannerMsg.innerHTML = `<strong>LAB MODE ACTIVE:</strong> Endpoints are vulnerable for manual OWASP Top 10 testing. Toggle to <em>SECURE</em> to test security controls.`;
    drawerMode.textContent = 'LAB (AUDITABLE)';
    drawerMode.className = 'text-danger';
  } else {
    badge.className = 'mode-pill secure-mode';
    text.textContent = '🛡️ SECURE MODE: Hardened';
    banner.className = 'global-banner secure-banner';
    bannerMsg.innerHTML = `<strong>SECURE MODE ACTIVE:</strong> Robust defenses, parameterized queries, input validation, and CSP headers are active.`;
    drawerMode.textContent = 'SECURE (HARDENED)';
    drawerMode.className = 'text-success';
  }
}

async function toggleSecurityMode() {
  const nextMode = state.securityMode === 'lab' ? 'secure' : 'lab';
  try {
    const res = await apiFetch('/api/security/mode', {
      method: 'POST',
      body: JSON.stringify({ mode: nextMode })
    });
    const data = await res.json();
    if (data.success) {
      state.securityMode = data.mode;
      updateSecurityModeUI();
      logToDrawerConsole(`[MODE SWITCH] Switched security mode to ${data.mode.toUpperCase()}`);
      if (document.getElementById('view-logs').classList.contains('active')) {
        loadAuditLogs();
      }
    }
  } catch (e) {
    alert('Failed to toggle security mode: ' + e.message);
  }
}

document.getElementById('toggleSecurityModeBtn').onclick = toggleSecurityMode;
document.getElementById('drawerToggleModeBtn').onclick = toggleSecurityMode;

// ==========================================
// 4. AUTHENTICATION & SESSIONS
// ==========================================
async function checkAuthStatus() {
  if (!state.token) {
    updateAuthWidget();
    return;
  }
  try {
    const res = await apiFetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      state.currentUser = data.user;
    } else {
      state.token = '';
      localStorage.removeItem('invoease_token');
      state.currentUser = null;
    }
  } catch (e) {
    state.currentUser = null;
  }
  updateAuthWidget();
}

function updateAuthWidget() {
  const widget = document.getElementById('userAuthWidget');
  if (state.currentUser) {
    widget.innerHTML = `
      <div class="user-profile-badge">
        <span class="user-name">👤 ${escapeHtml(state.currentUser.username)} <span class="badge-role">${state.currentUser.role}</span></span>
        <button class="btn btn-xs btn-secondary" id="logoutBtn">Sign Out</button>
      </div>
    `;
    document.getElementById('logoutBtn').onclick = logoutUser;
  } else {
    widget.innerHTML = `<button class="btn btn-sm btn-primary" id="openLoginModalBtn">Sign In</button>`;
    document.getElementById('openLoginModalBtn').onclick = () => openAuthModal('login');
  }
}

function setupAuthModal() {
  const backdrop = document.getElementById('authModalBackdrop');
  const closeBtn = document.getElementById('closeAuthModalBtn');
  const tabLogin = document.getElementById('tabLoginBtn');
  const tabReg = document.getElementById('tabRegisterBtn');
  const form = document.getElementById('authForm');
  const extraFields = document.getElementById('registerExtraFields');
  const submitBtn = document.getElementById('authSubmitBtn');
  const errorMsg = document.getElementById('authErrorMsg');

  let activeAuthTab = 'login';

  window.openAuthModal = (tab = 'login') => {
    activeAuthTab = tab;
    errorMsg.classList.add('hidden');
    backdrop.classList.add('active');
    if (tab === 'login') {
      tabLogin.classList.add('active');
      tabReg.classList.remove('active');
      extraFields.classList.add('hidden');
      submitBtn.textContent = 'Sign In';
      document.getElementById('authModalTitle').textContent = 'Sign In to InvoEase';
    } else {
      tabReg.classList.add('active');
      tabLogin.classList.remove('active');
      extraFields.classList.remove('hidden');
      submitBtn.textContent = 'Create Account';
      document.getElementById('authModalTitle').textContent = 'Create New Account';
    }
  };

  closeBtn.onclick = () => backdrop.classList.remove('active');
  backdrop.onclick = (e) => {
    if (e.target === backdrop) backdrop.classList.remove('active');
  };

  tabLogin.onclick = (e) => { e.preventDefault(); openAuthModal('login'); };
  tabReg.onclick = (e) => { e.preventDefault(); openAuthModal('register'); };

  // Fast Demo Login Buttons
  document.getElementById('quickLoginAliceBtn').onclick = () => quickLogin('alice_dev', 'Password123!');
  document.getElementById('quickLoginBobBtn').onclick = () => quickLogin('bob_designer', 'Password123!');
  document.getElementById('quickLoginAdminBtn').onclick = () => quickLogin('superadmin', 'Password123!');

  form.onsubmit = async (e) => {
    e.preventDefault();
    errorMsg.classList.add('hidden');

    const username = document.getElementById('authUsername').value.trim();
    const password = document.getElementById('authPassword').value;

    if (activeAuthTab === 'login') {
      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Login failed');
        }
        state.token = data.token;
        localStorage.setItem('invoease_token', data.token);
        state.currentUser = data.user;
        updateAuthWidget();
        backdrop.classList.remove('active');
        loadDashboardData();
        logToDrawerConsole(`[AUTH] Successfully logged in as: ${data.user.username} (${data.user.role})`);
      } catch (err) {
        errorMsg.textContent = err.message;
        errorMsg.classList.remove('hidden');
        logToDrawerConsole(`[AUTH ERROR] Login failed: ${err.message}`);
      }
    } else {
      // Register
      const payload = {
        username,
        password,
        email: document.getElementById('authEmail').value.trim(),
        business_name: document.getElementById('authBusinessName').value.trim(),
        gstin: document.getElementById('authGSTIN').value.trim(),
        role: document.getElementById('authRole').value
      };
      try {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Registration failed');
        alert('Registration successful! Logging you in...');
        quickLogin(username, password);
      } catch (err) {
        errorMsg.textContent = err.message;
        errorMsg.classList.remove('hidden');
      }
    }
  };
}

async function quickLogin(username, password) {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');
    state.token = data.token;
    localStorage.setItem('invoease_token', data.token);
    state.currentUser = data.user;
    updateAuthWidget();
    document.getElementById('authModalBackdrop').classList.remove('active');
    loadDashboardData();
    logToDrawerConsole(`[DEMO AUTH] Fast logged in as: ${data.user.username} (Role: ${data.user.role})`);
  } catch (err) {
    alert('Quick login failed: ' + err.message);
  }
}

async function logoutUser() {
  await apiFetch('/api/auth/logout', { method: 'POST' });
  state.token = '';
  localStorage.removeItem('invoease_token');
  state.currentUser = null;
  updateAuthWidget();
  loadDashboardData();
  logToDrawerConsole('[AUTH] User logged out.');
}

// ==========================================
// 5. DASHBOARD & INVOICE LIST
// ==========================================
async function loadDashboardData() {
  const search = document.getElementById('invoiceSearchInput').value.trim();
  const status = state.activeStatusFilter;

  let url = `/api/invoices?search=${encodeURIComponent(search)}`;
  if (status) url += `&status=${encodeURIComponent(status)}`;

  try {
    const res = await apiFetch(url);
    if (res.status === 401) {
      renderUnauthenticatedDashboard();
      return;
    }
    const data = await res.json();
    if (res.ok) {
      state.invoices = data.invoices || [];
      renderDashboardMetrics(state.invoices);
      renderInvoicesTable(state.invoices);
    } else {
      // In Lab mode, SQL errors return 500 with error details (A05 / A03)
      document.getElementById('invoicesTableBody').innerHTML = `
        <tr>
          <td colspan="8" class="text-danger py-4">
            <strong>Database Error:</strong> ${escapeHtml(data.error || 'Failed to fetch invoices')}<br>
            ${data.query ? `<code>Query: ${escapeHtml(data.query)}</code>` : ''}
          </td>
        </tr>
      `;
      logToDrawerConsole(`[SQLi / DB Output]\n${JSON.stringify(data, null, 2)}`);
    }
  } catch (err) {
    console.error('Error loading dashboard:', err);
  }
}

function renderUnauthenticatedDashboard() {
  document.getElementById('statTotalInvoiced').textContent = '₹0.00';
  document.getElementById('statPaidRevenue').textContent = '₹0.00';
  document.getElementById('statPendingAmount').textContent = '₹0.00';
  document.getElementById('statGstCollected').textContent = '₹0.00';
  document.getElementById('invoicesTableBody').innerHTML = `
    <tr>
      <td colspan="8" class="text-center py-4">
        <p class="text-muted">You are currently browsing as a guest.</p>
        <button class="btn btn-sm btn-primary mt-1" onclick="openAuthModal('login')">Sign In to View Invoices</button>
      </td>
    </tr>
  `;
}

function renderDashboardMetrics(invoices) {
  let totalInvoiced = 0;
  let paidRevenue = 0;
  let pendingAmount = 0;
  let gstCollected = 0;
  let paidCount = 0;
  let pendingCount = 0;

  invoices.forEach((inv) => {
    const grand = parseFloat(inv.grand_total) || 0;
    const sgst = parseFloat(inv.sgst_amount) || 0;
    const cgst = parseFloat(inv.cgst_amount) || 0;

    totalInvoiced += grand;
    gstCollected += sgst + cgst;

    if (inv.status === 'Paid') {
      paidRevenue += grand;
      paidCount++;
    } else if (inv.status === 'Pending' || inv.status === 'Overdue') {
      pendingAmount += grand;
      pendingCount++;
    }
  });

  const curr = invoices[0]?.currency || '₹';
  document.getElementById('statTotalInvoiced').textContent = `${curr}${totalInvoiced.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
  document.getElementById('statInvoiceCount').textContent = `${invoices.length} Invoices Generated`;

  document.getElementById('statPaidRevenue').textContent = `${curr}${paidRevenue.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
  document.getElementById('statPaidCount').textContent = `${paidCount} Cleared payments`;

  document.getElementById('statPendingAmount').textContent = `${curr}${pendingAmount.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
  document.getElementById('statPendingCount').textContent = `${pendingCount} Invoices awaiting settlement`;

  document.getElementById('statGstCollected').textContent = `${curr}${gstCollected.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
}

function renderInvoicesTable(invoices) {
  const tbody = document.getElementById('invoicesTableBody');
  if (!invoices || invoices.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No invoices found matching criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = invoices
    .map((inv) => {
      const curr = inv.currency || '₹';
      const grand = (parseFloat(inv.grand_total) || 0).toFixed(2);
      const totalGst = ((parseFloat(inv.sgst_amount) || 0) + (parseFloat(inv.cgst_amount) || 0)).toFixed(2);
      const statusClass = (inv.status || 'Pending').toLowerCase();

      return `
        <tr>
          <td>#${inv.id}</td>
          <td><strong>${escapeHtml(inv.invoice_number)}</strong></td>
          <td>${inv.created_at ? new Date(inv.created_at).toLocaleDateString() : 'Today'}</td>
          <td>${escapeHtml(inv.client_name)}</td>
          <td><strong>${curr}${grand}</strong></td>
          <td>${curr}${totalGst}</td>
          <td><span class="status-badge ${statusClass}">${inv.status}</span></td>
          <td>
            <div class="flex-row gap-1">
              <button class="btn btn-xs btn-outline-primary" onclick="viewInvoiceDetails(${inv.id})">View</button>
              <button class="btn btn-xs btn-outline-danger" onclick="deleteInvoice(${inv.id})">Delete</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

// Search and filter listeners
document.getElementById('invoiceSearchInput').addEventListener('input', debounce(loadDashboardData, 300));

document.getElementById('statusFilterPills').addEventListener('click', (e) => {
  if (e.target.classList.contains('pill')) {
    document.querySelectorAll('#statusFilterPills .pill').forEach((p) => p.classList.remove('active'));
    e.target.classList.add('active');
    state.activeStatusFilter = e.target.getAttribute('data-status');
    loadDashboardData();
  }
});

document.getElementById('refreshDashboardBtn').onclick = loadDashboardData;

// Quick Dashboard Testing Actions
document.getElementById('quickTestIdorBtn').onclick = async () => {
  logToDrawerConsole("Testing IDOR (A01): Fetching Invoice ID #2 (belongs to Bob)...");
  await viewInvoiceDetails(2);
};

document.getElementById('quickTestSqliBtn').onclick = async () => {
  const input = document.getElementById('invoiceSearchInput');
  input.value = "' OR 1=1 --";
  logToDrawerConsole("Testing SQL Injection (A03): Executing search with ' OR 1=1 --");
  await loadDashboardData();
};

document.getElementById('quickTestPrivilegeBtn').onclick = async () => {
  logToDrawerConsole('Testing Privilege Escalation (A01): Requesting /api/admin/users...');
  try {
    const res = await apiFetch('/api/admin/users');
    const data = await res.json();
    logToDrawerConsole(`Response (${res.status}):\n${JSON.stringify(data, null, 2)}`);
    if (res.ok) {
      alert(`Privilege Escalation Test:\nReceived ${data.users.length} user records! In Lab mode, non-admin role check is bypassed.`);
    } else {
      alert(`Protected in Secure Mode:\nStatus ${res.status}: ${data.error}`);
    }
  } catch (e) {
    logToDrawerConsole(`Error: ${e.message}`);
  }
};

async function viewInvoiceDetails(id) {
  try {
    const res = await apiFetch(`/api/invoices/${id}`);
    const data = await res.json();
    logToDrawerConsole(`GET /api/invoices/${id} -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);

    if (!res.ok) {
      alert(`Access Check (A01): ${data.error}`);
      return;
    }

    const inv = data.invoice;
    // Populate form and switch to generator view to view invoice
    populateFormWithInvoice(inv);
    switchView('generator');
  } catch (e) {
    alert('Failed to load invoice: ' + e.message);
  }
}

async function deleteInvoice(id) {
  if (!confirm(`Are you sure you want to delete Invoice #${id}? In Lab mode, this tests IDOR deletion.`)) return;

  try {
    const res = await apiFetch(`/api/invoices/${id}`, { method: 'DELETE' });
    const data = await res.json();
    logToDrawerConsole(`DELETE /api/invoices/${id} -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);

    if (res.ok) {
      alert(data.message || 'Invoice deleted.');
      loadDashboardData();
    } else {
      alert(`Deletion Blocked: ${data.error}`);
    }
  } catch (e) {
    alert('Delete error: ' + e.message);
  }
}

// ==========================================
// 6. INVOICE GENERATOR & LIVE A4 PREVIEW
// ==========================================
function setupInvoiceGenerator() {
  renderItemsList();
  renderLivePreview();

  document.getElementById('genAddItemBtn').onclick = () => {
    state.items.push({ desc: '', qty: 1, price: 0 });
    renderItemsList();
    renderLivePreview();
  };

  // Input change listeners
  const inputsToListen = [
    'genFromName', 'genFromGST', 'genFromEmail', 'genFromAddress',
    'genClientName', 'genClientGST', 'genClientEmail', 'genClientAddress',
    'genSGST', 'genCGST', 'genDiscount', 'genCurrency', 'genNotes'
  ];

  inputsToListen.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', () => {
        if (id === 'genCurrency') {
          document.getElementById('activeCurrencyDisplay').textContent = el.value;
          document.querySelectorAll('.currency-symbol').forEach((s) => (s.textContent = el.value));
        }
        renderLivePreview();
      });
    }
  });

  // Load Profile button
  document.getElementById('loadProfileToInvoiceBtn').onclick = () => {
    if (!state.currentUser) {
      alert('Please sign in first to load your profile details.');
      return;
    }
    document.getElementById('genFromName').value = state.currentUser.business_name || state.currentUser.username;
    document.getElementById('genFromGST').value = state.currentUser.gstin || '';
    document.getElementById('genFromEmail').value = state.currentUser.email || '';
    document.getElementById('genFromAddress').value = state.currentUser.address || '';
    renderLivePreview();
  };

  // File Upload (A08 Integrity Testing)
  document.getElementById('uploadLogoBtn').onclick = async () => {
    const fileInput = document.getElementById('logoFileInput');
    if (!fileInput.files || fileInput.files.length === 0) {
      alert('Please select a file to upload.');
      return;
    }

    const formData = new FormData();
    formData.append('logo', fileInput.files[0]);

    try {
      const res = await apiFetch('/api/upload/logo', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      logToDrawerConsole(`POST /api/upload/logo -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);

      if (res.ok) {
        state.currentLogoUrl = data.filePath;
        showLogoPreview(data.filePath);
        renderLivePreview();
        alert('Logo uploaded successfully.');
      } else {
        alert(`Upload Rejected (A08): ${data.error}`);
      }
    } catch (e) {
      alert('Upload failed: ' + e.message);
    }
  };

  // SSRF Fetch Remote Logo (A10 Testing)
  document.getElementById('fetchRemoteLogoBtn').onclick = async () => {
    const url = document.getElementById('remoteLogoUrlInput').value.trim();
    if (!url) {
      alert('Please enter a URL to fetch (e.g. http://127.0.0.1:3000/api/security/mode)');
      return;
    }

    logToDrawerConsole(`Testing SSRF (A10): Requesting server to fetch: ${url}`);
    try {
      const res = await apiFetch('/api/fetch-remote-logo', {
        method: 'POST',
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      logToDrawerConsole(`SSRF Response (${res.status}):\n${JSON.stringify(data, null, 2)}`);

      if (res.ok) {
        alert(`SSRF Fetch Result:\nStatus: ${data.status || 200}\nPreview: ${data.dataPreview || 'Fetched successfully'}`);
      } else {
        alert(`SSRF Defense (A10 Active):\n${data.error}`);
      }
    } catch (e) {
      alert('SSRF Error: ' + e.message);
    }
  };

  document.getElementById('removeLogoBtn').onclick = () => {
    state.currentLogoUrl = '';
    document.getElementById('logoPreviewContainer').classList.add('hidden');
    renderLivePreview();
  };

  // Clear Form
  document.getElementById('resetInvoiceFormBtn').onclick = () => {
    state.items = [{ desc: 'Consulting Services', qty: 1, price: 5000 }];
    document.getElementById('genClientName').value = '';
    document.getElementById('genClientGST').value = '';
    document.getElementById('genClientEmail').value = '';
    document.getElementById('genClientAddress').value = '';
    document.getElementById('genNotes').value = '';
    state.currentLogoUrl = '';
    renderItemsList();
    renderLivePreview();
  };

  // Save to DB
  document.getElementById('saveInvoiceToDbBtn').onclick = saveInvoiceToDatabase;

  // Print & PDF
  document.getElementById('printInvoiceBtn').onclick = () => window.print();
  document.getElementById('downloadPdfBtn').onclick = downloadInvoicePdf;
}

function showLogoPreview(url) {
  const container = document.getElementById('logoPreviewContainer');
  const img = document.getElementById('currentLogoImg');
  img.src = url;
  container.classList.remove('hidden');
}

function renderItemsList() {
  const container = document.getElementById('genItemsList');
  container.innerHTML = state.items
    .map(
      (item, index) => `
      <div class="item-row" data-index="${index}">
        <input type="text" class="item-desc" placeholder="Service description" value="${escapeHtml(item.desc)}" />
        <input type="number" class="item-qty" placeholder="1" value="${item.qty}" step="1" />
        <input type="number" class="item-price" placeholder="0" value="${item.price}" step="0.01" />
        <div class="item-line-total">${document.getElementById('genCurrency').value}${(item.qty * item.price).toFixed(2)}</div>
        <button class="btn-remove-row" onclick="removeItemRow(${index})">×</button>
      </div>
    `
    )
    .join('');

  // Row input event bindings
  container.querySelectorAll('.item-row').forEach((row) => {
    const idx = parseInt(row.getAttribute('data-index'), 10);
    const descInput = row.querySelector('.item-desc');
    const qtyInput = row.querySelector('.item-qty');
    const priceInput = row.querySelector('.item-price');

    const updateItem = () => {
      state.items[idx].desc = descInput.value;
      state.items[idx].qty = parseFloat(qtyInput.value) || 0;
      state.items[idx].price = parseFloat(priceInput.value) || 0;
      row.querySelector('.item-line-total').textContent = `${document.getElementById('genCurrency').value}${(state.items[idx].qty * state.items[idx].price).toFixed(2)}`;
      renderLivePreview();
    };

    descInput.addEventListener('input', updateItem);
    qtyInput.addEventListener('input', updateItem);
    priceInput.addEventListener('input', updateItem);
  });
}

window.removeItemRow = function (index) {
  if (state.items.length <= 1) {
    alert('Invoice must have at least one line item.');
    return;
  }
  state.items.splice(index, 1);
  renderItemsList();
  renderLivePreview();
};

function renderLivePreview() {
  const preview = document.getElementById('invoicePreviewSheet');
  const currency = document.getElementById('genCurrency').value;

  const fromName = document.getElementById('genFromName').value || 'Your Business Name';
  const fromGST = document.getElementById('genFromGST').value || '27ABCDE1234F1Z5';
  const fromEmail = document.getElementById('genFromEmail').value || 'billing@freelancer.studio';
  const fromAddress = document.getElementById('genFromAddress').value || '123 Tech Park, India';

  const clientName = document.getElementById('genClientName').value || 'Client Name / Business';
  const clientGST = document.getElementById('genClientGST').value || 'Client GSTIN';
  const clientEmail = document.getElementById('genClientEmail').value || 'client@company.com';
  const clientAddress = document.getElementById('genClientAddress').value || 'Commercial Center, City';

  const sgstRate = parseFloat(document.getElementById('genSGST').value) || 0;
  const cgstRate = parseFloat(document.getElementById('genCGST').value) || 0;
  const discountRate = parseFloat(document.getElementById('genDiscount').value) || 0;
  const notes = document.getElementById('genNotes').value;

  let subtotal = 0;
  state.items.forEach((item) => {
    subtotal += (item.qty || 0) * (item.price || 0);
  });

  const sgstAmt = (subtotal * sgstRate) / 100;
  const cgstAmt = (subtotal * cgstRate) / 100;
  const discountAmt = (subtotal * discountRate) / 100;
  const grandTotal = subtotal + sgstAmt + cgstAmt - discountAmt;

  // Stored / Reflected XSS testing condition (A03):
  // In Lab mode, notes/items are rendered as raw innerHTML. In Secure mode, sanitized!
  const renderField = (val) => {
    return state.securityMode === 'lab' ? val : escapeHtml(val);
  };

  const rowsHtml = state.items
    .map(
      (item) => `
      <tr>
        <td>${renderField(item.desc || 'Item description')}</td>
        <td class="text-right">${item.qty}</td>
        <td class="text-right">${currency}${(item.price || 0).toFixed(2)}</td>
        <td class="text-right"><strong>${currency}${((item.qty || 0) * (item.price || 0)).toFixed(2)}</strong></td>
      </tr>
    `
    )
    .join('');

  preview.innerHTML = `
    <div class="sheet-header">
      <div>
        <div class="sheet-title">TAX INVOICE</div>
        <p style="font-size: 11px; color: #6b7280;">GST Compliant Billing Document</p>
        ${state.currentLogoUrl ? `<img src="${state.currentLogoUrl}" style="max-height: 48px; margin-top: 10px;" alt="Logo" />` : ''}
      </div>
      <div class="sheet-meta">
        <p><strong>Invoice #:</strong> INV-${Date.now().toString().slice(-6)}</p>
        <p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p>
        <p><strong>Place of Supply:</strong> India</p>
      </div>
    </div>

    <div class="sheet-addresses">
      <div class="address-block">
        <h4>Billed By (Freelancer):</h4>
        <p><strong>${renderField(fromName)}</strong></p>
        <p>${renderField(fromAddress)}</p>
        <p>Email: ${renderField(fromEmail)}</p>
        <p><strong>GSTIN:</strong> ${renderField(fromGST)}</p>
      </div>
      <div class="address-block">
        <h4>Billed To (Client):</h4>
        <p><strong>${renderField(clientName)}</strong></p>
        <p>${renderField(clientAddress)}</p>
        <p>Email: ${renderField(clientEmail)}</p>
        <p><strong>GSTIN:</strong> ${renderField(clientGST)}</p>
      </div>
    </div>

    <table class="sheet-table">
      <thead>
        <tr>
          <th>Description</th>
          <th class="text-right">Qty</th>
          <th class="text-right">Unit Price</th>
          <th class="text-right">Amount</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
    </table>

    <div class="sheet-totals-area">
      <table class="totals-table">
        <tr>
          <td>Subtotal:</td>
          <td>${currency}${subtotal.toFixed(2)}</td>
        </tr>
        <tr>
          <td>SGST (${sgstRate}%):</td>
          <td>+ ${currency}${sgstAmt.toFixed(2)}</td>
        </tr>
        <tr>
          <td>CGST (${cgstRate}%):</td>
          <td>+ ${currency}${cgstAmt.toFixed(2)}</td>
        </tr>
        ${
          discountRate > 0
            ? `<tr>
                <td>Discount (${discountRate}%):</td>
                <td style="color: #ef4444;">- ${currency}${discountAmt.toFixed(2)}</td>
              </tr>`
            : ''
        }
        <tr class="grand-total-row">
          <td>Grand Total:</td>
          <td>${currency}${grandTotal.toFixed(2)}</td>
        </tr>
      </table>
    </div>

    <div class="sheet-footer">
      <p><strong>Notes & Terms:</strong></p>
      <p>${renderField(notes || 'Payment due within 15 days from issuance. Please transfer to the specified account.')}</p>
    </div>
  `;
}

function populateFormWithInvoice(inv) {
  document.getElementById('genClientName').value = inv.client_name || '';
  document.getElementById('genClientGST').value = inv.client_gstin || '';
  document.getElementById('genClientEmail').value = inv.client_email || '';
  document.getElementById('genClientAddress').value = inv.client_address || '';
  document.getElementById('genCurrency').value = inv.currency || '₹';
  document.getElementById('genSGST').value = inv.sgst_rate || 9;
  document.getElementById('genCGST').value = inv.cgst_rate || 9;
  document.getElementById('genDiscount').value = inv.discount_rate || 0;
  document.getElementById('genNotes').value = inv.notes || '';

  try {
    state.items = JSON.parse(inv.items_json);
  } catch (e) {
    state.items = [{ desc: 'Service item', qty: 1, price: inv.subtotal }];
  }

  renderItemsList();
  renderLivePreview();
}

async function saveInvoiceToDatabase() {
  if (!state.currentUser) {
    alert('Please sign in first to save invoices to your account.');
    openAuthModal('login');
    return;
  }

  const payload = {
    client_name: document.getElementById('genClientName').value.trim(),
    client_gstin: document.getElementById('genClientGST').value.trim(),
    client_email: document.getElementById('genClientEmail').value.trim(),
    client_address: document.getElementById('genClientAddress').value.trim(),
    currency: document.getElementById('genCurrency').value,
    items: state.items,
    sgst_rate: parseFloat(document.getElementById('genSGST').value) || 0,
    cgst_rate: parseFloat(document.getElementById('genCGST').value) || 0,
    discount_rate: parseFloat(document.getElementById('genDiscount').value) || 0,
    notes: document.getElementById('genNotes').value.trim(),
    status: 'Pending'
  };

  try {
    const res = await apiFetch('/api/invoices', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    logToDrawerConsole(`POST /api/invoices -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);

    if (res.ok) {
      alert(`Invoice saved successfully! Invoice #: ${data.invoice_number}`);
      loadDashboardData();
      switchView('dashboard');
    } else {
      alert(`Save Failed (A04 Validation): ${data.error}`);
    }
  } catch (e) {
    alert('Error saving invoice: ' + e.message);
  }
}

async function downloadInvoicePdf() {
  const element = document.getElementById('invoicePreviewSheet');
  const { jsPDF } = window.jspdf;
  const pdf = new jsPDF('p', 'pt', 'a4');

  const canvas = await html2canvas(element, { scale: 2 });
  const imgData = canvas.toDataURL('image/png');
  const width = pdf.internal.pageSize.getWidth();
  const height = (canvas.height * width) / canvas.width;

  pdf.addImage(imgData, 'PNG', 0, 0, width, height);
  pdf.save(`Invoice_${Date.now()}.pdf`);
}

// ==========================================
// 7. CLIENTS DIRECTORY
// ==========================================
async function loadClientsData() {
  const grid = document.getElementById('clientsGrid');
  const select = document.getElementById('quickClientSelect');

  try {
    const res = await apiFetch('/api/clients');
    if (!res.ok) {
      grid.innerHTML = `<p class="text-muted">Please sign in to view your client directory.</p>`;
      return;
    }
    const data = await res.json();
    state.clients = data.clients || [];

    // Populate quick select
    select.innerHTML = `<option value="">-- Choose Existing Client --</option>` +
      state.clients.map((c) => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');

    select.onchange = () => {
      const selected = state.clients.find((c) => c.id == select.value);
      if (selected) {
        document.getElementById('genClientName').value = selected.name;
        document.getElementById('genClientGST').value = selected.gstin || '';
        document.getElementById('genClientEmail').value = selected.email || '';
        document.getElementById('genClientAddress').value = selected.address || '';
        renderLivePreview();
      }
    };

    if (state.clients.length === 0) {
      grid.innerHTML = `<p class="text-muted">No clients saved yet. Add clients to auto-populate invoices.</p>`;
      return;
    }

    grid.innerHTML = state.clients
      .map(
        (c) => `
        <div class="client-card">
          <div class="client-card-header">
            <span class="client-name">${escapeHtml(c.name)}</span>
            <button class="btn btn-xs btn-outline-primary" onclick="quickBillClient(${c.id})">+ Invoice</button>
          </div>
          <div class="client-detail-row">📧 ${escapeHtml(c.email || 'No email')}</div>
          <div class="client-detail-row">🏛️ GSTIN: ${escapeHtml(c.gstin || 'Unregistered')}</div>
          <div class="client-detail-row">📍 ${escapeHtml(c.address || 'No address')}</div>
        </div>
      `
      )
      .join('');
  } catch (e) {
    console.error('Clients fetch error:', e);
  }
}

window.quickBillClient = function (id) {
  const client = state.clients.find((c) => c.id === id);
  if (client) {
    document.getElementById('genClientName').value = client.name;
    document.getElementById('genClientGST').value = client.gstin || '';
    document.getElementById('genClientEmail').value = client.email || '';
    document.getElementById('genClientAddress').value = client.address || '';
    renderLivePreview();
    switchView('generator');
  }
};

document.getElementById('openAddClientModalBtn').onclick = () => {
  document.getElementById('clientModalBackdrop').classList.add('active');
};
document.getElementById('closeClientModalBtn').onclick = () => {
  document.getElementById('clientModalBackdrop').classList.remove('active');
};
document.getElementById('addClientForm').onsubmit = async (e) => {
  e.preventDefault();
  const payload = {
    name: document.getElementById('newClientName').value.trim(),
    email: document.getElementById('newClientEmail').value.trim(),
    gstin: document.getElementById('newClientGSTIN').value.trim(),
    address: document.getElementById('newClientAddress').value.trim()
  };
  try {
    const res = await apiFetch('/api/clients', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      document.getElementById('clientModalBackdrop').classList.remove('active');
      document.getElementById('addClientForm').reset();
      loadClientsData();
      alert('Client added!');
    }
  } catch (e) {
    alert('Failed to add client: ' + e.message);
  }
};

// ==========================================
// 8. AUDIT LOGS & SYSTEM INFO
// ==========================================
async function loadAuditLogs() {
  const tbody = document.getElementById('auditLogsTableBody');
  try {
    const res = await apiFetch('/api/security/logs');
    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-muted text-center py-4">Sign in to view security audit logs.</td></tr>`;
      return;
    }
    const data = await res.json();
    const logs = data.logs || [];
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-muted text-center py-4">No audit events recorded yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = logs
      .map(
        (l) => `
        <tr>
          <td><small>${new Date(l.timestamp).toLocaleTimeString()}</small></td>
          <td><code>${escapeHtml(l.ip || '127.0.0.1')}</code></td>
          <td>${l.user_id ? `#${l.user_id}` : '<span class="text-muted">Guest</span>'}</td>
          <td><strong>${escapeHtml(l.action)}</strong></td>
          <td><span class="status-badge ${l.status === 'SUCCESS' ? 'paid' : 'overdue'}">${l.status}</span></td>
          <td>${escapeHtml(l.details || '')}</td>
        </tr>
      `
      )
      .join('');
  } catch (e) {
    console.error('Audit logs error:', e);
  }
}

document.getElementById('refreshLogsBtn').onclick = loadAuditLogs;

document.getElementById('fetchSystemInfoBtn').onclick = async () => {
  const envBox = document.getElementById('envConfigPreview');
  const depBox = document.getElementById('depConfigPreview');

  try {
    const resEnv = await apiFetch('/api/debug/environment');
    const dataEnv = await resEnv.json();
    envBox.textContent = `Status: ${resEnv.status}\n` + JSON.stringify(dataEnv, null, 2);

    const resDep = await apiFetch('/api/system/dependencies');
    const dataDep = await resDep.json();
    depBox.textContent = `Status: ${resDep.status}\n` + JSON.stringify(dataDep, null, 2);

    logToDrawerConsole(`A05/A06 Check:\nEnvironment: ${resEnv.status} (${resEnv.ok ? 'Exposed in Lab' : 'Blocked in Secure'})\nDependencies: ${resDep.status}`);
  } catch (e) {
    envBox.textContent = 'Error: ' + e.message;
  }
};

// ==========================================
// 9. OWASP TOP 10 LAB ACCORDION & RUNNERS
// ==========================================
function setupOwaspDrawer() {
  const drawer = document.getElementById('owaspDrawer');
  const backdrop = document.getElementById('owaspDrawerBackdrop');
  const openBtn = document.getElementById('openOwaspDrawerBtn');
  const closeBtn = document.getElementById('closeOwaspDrawerBtn');
  const clearConsoleBtn = document.getElementById('clearConsoleBtn');

  openBtn.onclick = () => {
    drawer.classList.add('active');
    backdrop.classList.add('active');
  };

  const closeDrawer = () => {
    drawer.classList.remove('active');
    backdrop.classList.remove('active');
  };

  closeBtn.onclick = closeDrawer;
  backdrop.onclick = closeDrawer;

  clearConsoleBtn.onclick = () => {
    document.getElementById('drawerConsoleOutput').textContent = '// Console cleared.';
  };
}

async function loadOwaspMatrix() {
  try {
    const res = await fetch('/api/security/matrix');
    state.matrix = await res.json();
    renderOwaspAccordion();
  } catch (e) {
    console.error('Matrix error:', e);
  }
}

function renderOwaspAccordion() {
  const list = document.getElementById('owaspAccordionList');
  list.innerHTML = state.matrix
    .map(
      (item) => `
      <div class="owasp-card" id="card-${item.id}">
        <div class="owasp-card-header" onclick="toggleOwaspCard('${item.id}')">
          <div class="owasp-card-title">
            <span class="badge badge-info">${item.id}</span>
            <span>${escapeHtml(item.title)}</span>
          </div>
          <span class="accordion-arrow">▼</span>
        </div>
        <div class="owasp-card-content">
          <p><strong>Endpoint / Target:</strong> <code>${escapeHtml(item.endpoint)}</code></p>
          <p class="mt-1">${escapeHtml(item.description)}</p>
          
          <div class="test-instructions">
            <strong>Lab Mode Behavior:</strong> ${escapeHtml(item.labBehavior)}<br>
            <strong class="mt-1">Secure Mode Behavior:</strong> ${escapeHtml(item.secureBehavior)}
          </div>

          <p><strong>Manual Testing Guide:</strong> ${escapeHtml(item.testHint)}</p>

          <div class="mt-3">
            <button class="btn btn-xs btn-outline-danger" onclick="runAutomatedOwaspTest('${item.id}')">
              ⚡ Execute Test Request
            </button>
          </div>
        </div>
      </div>
    `
    )
    .join('');
}

window.toggleOwaspCard = function (id) {
  const card = document.getElementById(`card-${id}`);
  card.classList.toggle('open');
};

window.runAutomatedOwaspTest = async function (id) {
  logToDrawerConsole(`--- Executing Test for ${id} in ${state.securityMode.toUpperCase()} Mode ---`);

  switch (id) {
    case 'A01': {
      // Test IDOR: Fetch Bob's invoice (ID 2)
      const res = await apiFetch('/api/invoices/2');
      const data = await res.json();
      logToDrawerConsole(`GET /api/invoices/2 -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);
      break;
    }
    case 'A02': {
      // Inspect Cookies
      logToDrawerConsole(`document.cookie in browser:\n"${document.cookie || '(No accessible cookies found - HttpOnly may be active)'}"`);
      break;
    }
    case 'A03': {
      // Test SQLi on Search
      const res = await apiFetch(`/api/invoices?search=${encodeURIComponent("' OR 1=1 --")}`);
      const data = await res.json();
      logToDrawerConsole(`GET /api/invoices?search=' OR 1=1 -- -> Status: ${res.status}\nResult: Returned ${data.invoices ? data.invoices.length : 0} records.`);
      break;
    }
    case 'A04': {
      // Test Business Logic: Negative Qty
      const testInvoice = {
        client_name: 'Test Exploit Client',
        currency: '₹',
        items: [{ desc: 'Tampered Item', qty: -10, price: 5000 }],
        sgst_rate: 9,
        cgst_rate: 9,
        discount_rate: 150
      };
      const res = await apiFetch('/api/invoices', {
        method: 'POST',
        body: JSON.stringify(testInvoice)
      });
      const data = await res.json();
      logToDrawerConsole(`POST /api/invoices (Negative Qty / 150% Discount) -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);
      break;
    }
    case 'A05': {
      const res = await apiFetch('/api/debug/environment');
      const data = await res.json();
      logToDrawerConsole(`GET /api/debug/environment -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);
      break;
    }
    case 'A06': {
      const res = await apiFetch('/api/system/dependencies');
      const data = await res.json();
      logToDrawerConsole(`GET /api/system/dependencies -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);
      break;
    }
    case 'A07': {
      // User enumeration test
      const res1 = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'non_existent_user_9999', password: 'password' })
      });
      const data1 = await res1.json();
      logToDrawerConsole(`Test 1 (Non-existent user): ${res1.status} -> ${data1.error}`);

      const res2 = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'alice_dev', password: 'wrongpassword' })
      });
      const data2 = await res2.json();
      logToDrawerConsole(`Test 2 (Existing user, bad password): ${res2.status} -> ${data2.error}`);
      break;
    }
    case 'A08': {
      logToDrawerConsole('A08 File Upload Test: Use the "Upload File" feature with an invalid extension (.html or .exe) in the Invoice Builder.');
      break;
    }
    case 'A09': {
      const res = await apiFetch('/api/security/logs');
      const data = await res.json();
      logToDrawerConsole(`GET /api/security/logs -> Status: ${res.status}\nFound ${data.logs ? data.logs.length : 0} audit logs.`);
      break;
    }
    case 'A10': {
      const res = await apiFetch('/api/fetch-remote-logo', {
        method: 'POST',
        body: JSON.stringify({ url: 'http://127.0.0.1:3000/api/security/mode' })
      });
      const data = await res.json();
      logToDrawerConsole(`POST /api/fetch-remote-logo (Target: 127.0.0.1) -> Status: ${res.status}\n${JSON.stringify(data, null, 2)}`);
      break;
    }
    default:
      logToDrawerConsole(`No runner defined for ${id}`);
  }
};

function logToDrawerConsole(msg) {
  const box = document.getElementById('drawerConsoleOutput');
  const timestamp = new Date().toLocaleTimeString();
  box.textContent = `[${timestamp}]\n${msg}\n\n` + box.textContent;
}

// ==========================================
// 10. UTILITIES
// ==========================================
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}
