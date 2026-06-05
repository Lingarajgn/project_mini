const API_BASE = 'http://127.0.0.1:8000';
const TOKEN_KEY = 'token';
const PROTECTED_PAGES = ['dashboard.html', 'tasks.html', 'routines.html'];

const api = {
    async request(path, options = {}) {
        const headers = {
            ...(options.body ? { 'Content-Type': 'application/json' } : {}),
            ...options.headers,
        };
        const token = getToken();

        if (token) {
            headers.Authorization = `Bearer ${token}`;
        }

        const response = await fetch(`${API_BASE}${path}`, {
            ...options,
            headers,
        });

        if (response.status === 401) {
            localStorage.removeItem(TOKEN_KEY);
            if (isProtectedPage()) {
                window.location.href = 'login.html';
            }
            throw new Error('Session expired. Please sign in again.');
        }

        const data = response.status === 204 ? null : await response.json().catch(() => null);

        if (!response.ok) {
            throw new Error(getApiError(data) || 'Something went wrong.');
        }

        return data;
    },
    get(path) {
        return this.request(path);
    },
    post(path, body) {
        return this.request(path, { method: 'POST', body: JSON.stringify(body) });
    },
    put(path, body) {
        return this.request(path, { method: 'PUT', body: JSON.stringify(body) });
    },
    patch(path, body) {
        return this.request(path, { method: 'PATCH', body: body ? JSON.stringify(body) : undefined });
    },
    delete(path) {
        return this.request(path, { method: 'DELETE' });
    },
};

function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

function getCurrentPage() {
    const page = window.location.pathname.split('/').pop();
    return page || 'index.html';
}

function isProtectedPage() {
    return PROTECTED_PAGES.includes(getCurrentPage());
}

function setMessage(el, text, isError = false) {
    if (!el) return;
    el.textContent = text;
    el.classList.toggle('error', isError);
}

function setLoading(el, text = 'Loading...') {
    if (!el) return;
    el.innerHTML = `<p class="muted loading">${text}</p>`;
}

function getApiError(data) {
    if (!data) return '';
    if (typeof data.detail === 'string') return data.detail;
    if (Array.isArray(data.detail)) {
        return data.detail.map((item) => item.msg || item.message || 'Invalid input').join(' ');
    }
    return data.message || '';
}

function escapeHtml(value = '') {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function setButtonLoading(button, isLoading, loadingText = 'Saving...') {
    if (!button) return;
    if (isLoading) {
        button.dataset.originalText = button.textContent;
        button.textContent = loadingText;
        button.disabled = true;
        return;
    }
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
    delete button.dataset.originalText;
}

function requireAuth() {
    if (!getToken() && isProtectedPage()) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

function logout() {
    localStorage.removeItem(TOKEN_KEY);
    window.location.href = 'login.html';
}

function formatDate(value) {
    return value ? new Date(value).toLocaleDateString() : 'No due date';
}

function formatStatus(value) {
    return value.replace(/_/g, ' ');
}

function getTaskPayload() {
    return {
        title: document.getElementById('taskTitle').value.trim(),
        description: document.getElementById('taskDescription').value.trim() || null,
        priority: document.getElementById('taskPriority').value,
        status: document.getElementById('taskStatus').value,
        due_date: document.getElementById('taskDueDate').value || null,
    };
}

function getRoutinePayload() {
    return {
        routine_name: document.getElementById('routineName').value.trim(),
        description: document.getElementById('routineDescription').value.trim() || null,
        start_time: document.getElementById('routineStartTime').value,
        end_time: document.getElementById('routineEndTime').value,
    };
}

async function registerUser(e) {
    e.preventDefault();
    const message = document.getElementById('registerMessage');
    const button = e.submitter;

    try {
        setButtonLoading(button, true, 'Creating...');
        await api.post('/auth/register', {
            fullname: document.getElementById('fullname').value.trim(),
            email: document.getElementById('email').value.trim(),
            password: document.getElementById('password').value,
        });
        setMessage(message, 'Registration successful. You can now sign in.', false);
        e.target.reset();
    } catch (err) {
        setMessage(message, err.message, true);
    } finally {
        setButtonLoading(button, false);
    }
}

async function loginUser(e) {
    e.preventDefault();
    const message = document.getElementById('loginMessage');
    const button = e.submitter;

    try {
        setButtonLoading(button, true, 'Signing in...');
        const data = await api.post('/auth/login', {
            email: document.getElementById('loginEmail').value.trim(),
            password: document.getElementById('loginPassword').value,
        });
        localStorage.setItem(TOKEN_KEY, data.access_token);
        setMessage(message, 'Login successful. Redirecting...', false);
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 400);
    } catch (err) {
        setMessage(message, err.message, true);
    } finally {
        setButtonLoading(button, false);
    }
}

async function loadDashboard() {
    if (!requireAuth()) return;

    const stats = document.getElementById('dashboardStats');
    const focus = document.getElementById('focusMessage');
    const routines = document.getElementById('totalRoutines');

    try {
        setLoading(stats, 'Loading dashboard...');
        setMessage(focus, 'Loading your summary...', false);
        const data = await api.get('/dashboard');
        const cards = [
            ['Total Tasks', data.total_tasks],
            ['Completed', data.completed_tasks],
            ['Pending', data.pending_tasks],
            ['Completion Rate', `${data.completion_rate}%`],
        ];

        stats.innerHTML = cards
            .map(
                ([label, value]) => `
                <article class="card stat-box">
                    <h3>${label}</h3>
                    <strong>${value}</strong>
                </article>
            `
            )
            .join('');
        routines.textContent = data.total_routines;
        setMessage(focus, `${data.completed_tasks} tasks completed out of ${data.total_tasks}.`, false);
    } catch (err) {
        stats.innerHTML = '<article class="card"><p class="message error">Unable to load dashboard.</p></article>';
        setMessage(focus, err.message, true);
    }
}

async function loadTasks() {
    if (!requireAuth()) return;

    const list = document.getElementById('taskList');
    const msg = document.getElementById('taskMessage');

    try {
        setLoading(list, 'Loading tasks...');
        const data = await api.get('/tasks');
        setMessage(msg, '', false);

        if (!data.length) {
            list.innerHTML = '<p class="muted">No tasks yet.</p>';
            return;
        }

        list.innerHTML = data.map(renderTask).join('');
    } catch (err) {
        list.innerHTML = '';
        setMessage(msg, err.message, true);
    }
}

function renderTask(task) {
    return `
        <article class="task-item" data-task-id="${task.id}">
            <div>
                <strong>${escapeHtml(task.title)}</strong>
                <div class="task-meta">${escapeHtml(task.description || 'No description')} - Priority: ${task.priority} - Status: ${formatStatus(task.status)}</div>
                <div class="task-meta">Due: ${formatDate(task.due_date)}</div>
            </div>
            <div class="item-actions">
                <span class="badge">${formatStatus(task.status)}</span>
                <button class="btn btn-secondary" data-action="edit-task">Edit</button>
                <button class="btn btn-secondary" data-action="complete-task" ${task.status === 'completed' ? 'disabled' : ''}>Complete</button>
                <button class="btn btn-danger" data-action="delete-task">Delete</button>
            </div>
        </article>
    `;
}

async function saveTask(e) {
    e.preventDefault();
    const msg = document.getElementById('taskMessage');
    const taskId = document.getElementById('taskId').value;
    const button = document.getElementById('taskSubmitBtn');
    const payload = getTaskPayload();

    try {
        setButtonLoading(button, true, taskId ? 'Updating...' : 'Adding...');
        if (taskId) {
            await api.put(`/tasks/${taskId}`, payload);
            setMessage(msg, 'Task updated successfully.', false);
        } else {
            await api.post('/tasks', payload);
            setMessage(msg, 'Task created successfully.', false);
        }
        setButtonLoading(button, false);
        resetTaskForm();
        await loadTasks();
    } catch (err) {
        setMessage(msg, err.message, true);
    } finally {
        setButtonLoading(button, false);
    }
}

async function handleTaskAction(e) {
    const button = e.target.closest('button[data-action]');
    if (!button) return;

    const item = button.closest('[data-task-id]');
    const taskId = item.dataset.taskId;
    const msg = document.getElementById('taskMessage');

    try {
        setButtonLoading(button, true, 'Working...');

        if (button.dataset.action === 'edit-task') {
            const task = await api.get(`/tasks/${taskId}`);
            fillTaskForm(task);
            setMessage(msg, 'Editing task. Update the form and save.', false);
            return;
        }

        if (button.dataset.action === 'complete-task') {
            await api.patch(`/tasks/${taskId}/complete`);
            setMessage(msg, 'Task marked complete.', false);
        }

        if (button.dataset.action === 'delete-task') {
            await api.delete(`/tasks/${taskId}`);
            setMessage(msg, 'Task deleted.', false);
        }

        await loadTasks();
    } catch (err) {
        setMessage(msg, err.message, true);
    } finally {
        setButtonLoading(button, false);
    }
}

function fillTaskForm(task) {
    document.getElementById('taskId').value = task.id;
    document.getElementById('taskTitle').value = task.title;
    document.getElementById('taskDescription').value = task.description || '';
    document.getElementById('taskPriority').value = task.priority;
    document.getElementById('taskStatus').value = task.status;
    document.getElementById('taskDueDate').value = task.due_date ? task.due_date.slice(0, 10) : '';
    document.getElementById('taskFormTitle').textContent = 'Update Task';
    document.getElementById('taskSubmitBtn').textContent = 'Update Task';
}

function resetTaskForm() {
    const form = document.getElementById('taskForm');
    if (!form) return;
    form.reset();
    document.getElementById('taskId').value = '';
    document.getElementById('taskFormTitle').textContent = 'Add Task';
    document.getElementById('taskSubmitBtn').textContent = 'Add Task';
}

async function loadRoutines() {
    if (!requireAuth()) return;

    const list = document.getElementById('routineList');
    const msg = document.getElementById('routineMessage');

    try {
        setLoading(list, 'Loading routines...');
        const data = await api.get('/routines');
        setMessage(msg, '', false);

        if (!data.length) {
            list.innerHTML = '<p class="muted">No routines yet.</p>';
            return;
        }

        list.innerHTML = data.map(renderRoutine).join('');
    } catch (err) {
        list.innerHTML = '';
        setMessage(msg, err.message, true);
    }
}

function renderRoutine(routine) {
    return `
        <article class="task-item" data-routine-id="${routine.id}">
            <div>
                <strong>${escapeHtml(routine.routine_name)}</strong>
                <div class="task-meta">${escapeHtml(routine.description || 'No description')}</div>
                <div class="task-meta">${routine.start_time} - ${routine.end_time}</div>
            </div>
            <div class="item-actions">
                <button class="btn btn-secondary" data-action="edit-routine">Edit</button>
                <button class="btn btn-danger" data-action="delete-routine">Delete</button>
            </div>
        </article>
    `;
}

async function saveRoutine(e) {
    e.preventDefault();
    const msg = document.getElementById('routineMessage');
    const routineId = document.getElementById('routineId').value;
    const button = document.getElementById('routineSubmitBtn');
    const payload = getRoutinePayload();

    try {
        setButtonLoading(button, true, routineId ? 'Updating...' : 'Adding...');
        if (routineId) {
            await api.put(`/routines/${routineId}`, payload);
            setMessage(msg, 'Routine updated successfully.', false);
        } else {
            await api.post('/routines', payload);
            setMessage(msg, 'Routine created successfully.', false);
        }
        setButtonLoading(button, false);
        resetRoutineForm();
        await loadRoutines();
    } catch (err) {
        setMessage(msg, err.message, true);
    } finally {
        setButtonLoading(button, false);
    }
}

async function handleRoutineAction(e) {
    const button = e.target.closest('button[data-action]');
    if (!button) return;

    const item = button.closest('[data-routine-id]');
    const routineId = item.dataset.routineId;
    const msg = document.getElementById('routineMessage');

    try {
        setButtonLoading(button, true, 'Working...');

        if (button.dataset.action === 'edit-routine') {
            const routine = await api.get(`/routines/${routineId}`);
            fillRoutineForm(routine);
            setMessage(msg, 'Editing routine. Update the form and save.', false);
            return;
        }

        await api.delete(`/routines/${routineId}`);
        setMessage(msg, 'Routine deleted.', false);
        await loadRoutines();
    } catch (err) {
        setMessage(msg, err.message, true);
    } finally {
        setButtonLoading(button, false);
    }
}

function fillRoutineForm(routine) {
    document.getElementById('routineId').value = routine.id;
    document.getElementById('routineName').value = routine.routine_name;
    document.getElementById('routineDescription').value = routine.description || '';
    document.getElementById('routineStartTime').value = routine.start_time.slice(0, 5);
    document.getElementById('routineEndTime').value = routine.end_time.slice(0, 5);
    document.getElementById('routineFormTitle').textContent = 'Update Routine';
    document.getElementById('routineSubmitBtn').textContent = 'Update Routine';
}

function resetRoutineForm() {
    const form = document.getElementById('routineForm');
    if (!form) return;
    form.reset();
    document.getElementById('routineId').value = '';
    document.getElementById('routineFormTitle').textContent = 'Add Routine';
    document.getElementById('routineSubmitBtn').textContent = 'Add Routine';
}

function bindButtons() {
    document.querySelectorAll('#logoutBtn').forEach((btn) => btn.addEventListener('click', logout));

    const registerForm = document.getElementById('registerForm');
    if (registerForm) registerForm.addEventListener('submit', registerUser);

    const loginForm = document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', loginUser);

    const taskForm = document.getElementById('taskForm');
    if (taskForm) taskForm.addEventListener('submit', saveTask);

    const taskList = document.getElementById('taskList');
    if (taskList) taskList.addEventListener('click', handleTaskAction);

    const routineForm = document.getElementById('routineForm');
    if (routineForm) routineForm.addEventListener('submit', saveRoutine);

    const routineList = document.getElementById('routineList');
    if (routineList) routineList.addEventListener('click', handleRoutineAction);
}

window.addEventListener('DOMContentLoaded', () => {
    if (!requireAuth()) return;

    bindButtons();

    if (document.getElementById('dashboardStats')) loadDashboard();
    if (document.getElementById('taskList')) loadTasks();
    if (document.getElementById('routineList')) loadRoutines();
});
