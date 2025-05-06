// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', () => {
    // Vulnerable: JWT stored in localStorage
    let currentUser = null;

    // Helper function to safely add event listeners
    const addEventListenerIfExists = (id, event, handler) => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener(event, handler);
        }
    };

    // Helper function to display results
    function displayResult(elementId, data, isError = false) {
        const resultElement = document.getElementById(elementId);
        if (!resultElement) return;
        
        resultElement.innerHTML = '';
        resultElement.className = 'result ' + (isError ? 'error' : 'success');
        
        if (typeof data === 'object') {
            resultElement.innerHTML = JSON.stringify(data, null, 2);
        } else {
            resultElement.innerHTML = data;
        }
    }

    // Helper function to handle form submissions
    async function handleFormSubmit(event, endpoint, method = 'POST') {
        event.preventDefault();
        const formData = new FormData(event.target);
        const data = {};
        formData.forEach((value, key) => data[key] = value);

        try {
            const response = await fetch(endpoint, {
                method,
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            displayResult(event.target.id + 'Result', result);
        } catch (error) {
            displayResult(event.target.id + 'Result', error.message, true);
        }
    }

    // Vulnerable Login Form Handler
    addEventListenerIfExists('loginForm', 'submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (response.ok) {
                // Vulnerable: Storing sensitive data in localStorage
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                currentUser = data.user;
                document.getElementById('loginMessage').textContent = 'Login successful!';
            } else {
                document.getElementById('loginMessage').textContent = data.error;
            }
        } catch (error) {
            document.getElementById('loginMessage').textContent = 'Error during login';
        }
    });

    // Vulnerable Search Handler (SQL Injection)
    addEventListenerIfExists('searchForm', 'submit', async (e) => {
        e.preventDefault();
        const query = document.getElementById('searchQuery').value;
        const page = document.getElementById('page').value;
        const limit = document.getElementById('limit').value;

        try {
            // Vulnerable: SQL Injection through query parameters
            const response = await fetch(`/api/search?q=${encodeURIComponent(query)}&page=${page}&limit=${limit}`);
            const results = await response.json();
            
            // Vulnerable: XSS in search results
            document.getElementById('searchResults').innerHTML = results
                .map(comment => `<div class="comment">${comment.content}</div>`)
                .join('');
        } catch (error) {
            document.getElementById('searchResults').textContent = 'Error during search';
        }
    });

    // Vulnerable Comment Handler (XSS)
    addEventListenerIfExists('commentForm', 'submit', async (e) => {
        e.preventDefault();
        const content = document.getElementById('commentContent').value;
        const userId = currentUser?.id;

        if (!userId) {
            alert('Please login first');
            return;
        }

        try {
            const response = await fetch('/api/comments', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, userId })
            });

            const data = await response.json();
            if (response.ok) {
                // Vulnerable: XSS in comment display
                document.getElementById('comments').innerHTML += 
                    `<div class="comment">${data.content}</div>`;
                document.getElementById('commentContent').value = '';
            }
        } catch (error) {
            console.error('Error posting comment:', error);
        }
    });

    // Vulnerable File Upload Handler
    addEventListenerIfExists('uploadForm', 'submit', async (e) => {
        e.preventDefault();
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];

        if (!file) {
            document.getElementById('uploadMessage').textContent = 'Please select a file';
            return;
        }

        try {
            // Vulnerable: No file type validation
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            if (response.ok) {
                document.getElementById('uploadMessage').textContent = 'File uploaded successfully';
            } else {
                document.getElementById('uploadMessage').textContent = data.error;
            }
        } catch (error) {
            document.getElementById('uploadMessage').textContent = 'Error uploading file';
        }
    });

    // Vulnerable Command Execution
    addEventListenerIfExists('commandForm', 'submit', async (e) => {
        e.preventDefault();
        const command = document.getElementById('command').value;

        try {
            const response = await fetch('/api/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command })
            });

            const data = await response.json();
            // Vulnerable: XSS in command output
            document.getElementById('commandOutput').innerHTML = 
                `<pre>${data.output}</pre>`;
        } catch (error) {
            document.getElementById('commandOutput').textContent = 'Error executing command';
        }
    });

    // Vulnerable User Update Handler (Mass Assignment)
    addEventListenerIfExists('massAssignmentForm', 'submit', async (e) => {
        e.preventDefault();
        const userId = document.getElementById('userId').value;
        const updates = {
            id: userId,
            email: document.getElementById('userEmail').value,
            role: document.getElementById('userRole').value,
            isAdmin: document.getElementById('userIsAdmin').value,
            password: document.getElementById('userPassword').value,
            apiKey: document.getElementById('userApiKey').value
        };

        try {
            const response = await fetch('/api/vulnerable/users/update', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(updates)
            });

            if (!response.ok) {
                const errorText = await response.text();
                try {
                    const errorJson = JSON.parse(errorText);
                    displayResult('massAssignmentResult', errorJson, true);
                } catch {
                    displayResult('massAssignmentResult', `Server error: ${errorText}`, true);
                }
                return;
            }

            const data = await response.json();
            displayResult('massAssignmentResult', data);
        } catch (error) {
            displayResult('massAssignmentResult', `Error: ${error.message}`, true);
        }
    });

    // Secure User Update Handler (Mass Assignment)
    addEventListenerIfExists('massAssignmentSecureForm', 'submit', async (e) => {
        e.preventDefault();
        const userId = document.getElementById('userIdSecure').value;
        const updates = {
            id: userId,
            email: document.getElementById('userEmailSecure').value,
            name: document.getElementById('userNameSecure').value
        };

        try {
            const response = await fetch('/api/secure/users/update', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(updates)
            });

            if (!response.ok) {
                const errorText = await response.text();
                try {
                    const errorJson = JSON.parse(errorText);
                    displayResult('massAssignmentSecureResult', errorJson, true);
                } catch {
                    displayResult('massAssignmentSecureResult', `Server error: ${errorText}`, true);
                }
                return;
            }

            const data = await response.json();
            displayResult('massAssignmentSecureResult', data);
        } catch (error) {
            displayResult('massAssignmentSecureResult', `Error: ${error.message}`, true);
        }
    });

    // Vulnerable Admin Action (CSRF)
    addEventListenerIfExists('deleteAllCommentsForm', 'submit', async (e) => {
        e.preventDefault();
        try {
            const response = await fetch('/api/admin/deleteAll', {
                method: 'POST',
                // Vulnerable: No CSRF token
            });

            const data = await response.json();
            if (response.ok) {
                document.getElementById('comments').innerHTML = '';
                alert('All comments deleted');
            }
        } catch (error) {
            console.error('Error deleting comments:', error);
        }
    });

    // Vulnerable Redirect Handler
    addEventListenerIfExists('redirectForm', 'submit', (e) => {
        e.preventDefault();
        const url = document.getElementById('redirectUrl').value;
        // Vulnerable: Open redirect
        window.location.href = `/redirect?url=${encodeURIComponent(url)}`;
    });

    // ===== VULNERABLE IMPLEMENTATIONS =====

    // SQL Injection (Vulnerable)
    addEventListenerIfExists('vulnerableSearchForm', 'submit', async (e) => {
        e.preventDefault();
        const query = document.getElementById('vulnerableSearchQuery')?.value;

        try {
            const response = await fetch(`/api/vulnerable/search?q=${encodeURIComponent(query)}`);
            const results = await response.json();
            
            const resultsElement = document.getElementById('vulnerableSearchResults');
            if (resultsElement) {
                resultsElement.innerHTML = results
                    .map(comment => `<div class="comment">${comment.content}</div>`)
                    .join('');
            }
        } catch (error) {
            const resultsElement = document.getElementById('vulnerableSearchResults');
            if (resultsElement) {
                resultsElement.textContent = 'Error during search';
            }
        }
    });

    // XSS (Vulnerable)
    addEventListenerIfExists('vulnerableCommentForm', 'submit', async (e) => {
        e.preventDefault();
        const content = document.getElementById('vulnerableCommentContent')?.value;

        try {
            const response = await fetch('/api/vulnerable/comments', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, userId: 1 })
            });

            const data = await response.json();
            if (response.ok) {
                const commentsElement = document.getElementById('vulnerableComments');
                if (commentsElement) {
                    commentsElement.innerHTML += 
                        `<div class="comment">${data.content}</div>`;
                }
                const contentElement = document.getElementById('vulnerableCommentContent');
                if (contentElement) {
                    contentElement.value = '';
                }
            }
        } catch (error) {
            console.error('Error posting comment:', error);
        }
    });

    // Command Injection (Vulnerable)
    addEventListenerIfExists('vulnerableCommandForm', 'submit', async (e) => {
        e.preventDefault();
        const command = document.getElementById('vulnerableCommand')?.value;

        try {
            const response = await fetch('/api/vulnerable/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command })
            });

            const data = await response.json();
            const outputElement = document.getElementById('vulnerableCommandOutput');
            if (outputElement) {
                outputElement.innerHTML = `<pre>${data.output}</pre>`;
            }
        } catch (error) {
            const outputElement = document.getElementById('vulnerableCommandOutput');
            if (outputElement) {
                outputElement.textContent = 'Error executing command';
            }
        }
    });

    // Authentication (Vulnerable)
    addEventListenerIfExists('vulnerableLoginForm', 'submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('vulnerableUsername')?.value;
        const password = document.getElementById('vulnerablePassword')?.value;

        try {
            const response = await fetch('/api/vulnerable/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            const messageElement = document.getElementById('vulnerableLoginMessage');
            if (messageElement) {
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));
                    messageElement.textContent = 'Login successful!';
                } else {
                    messageElement.textContent = data.error;
                }
            }
        } catch (error) {
            const messageElement = document.getElementById('vulnerableLoginMessage');
            if (messageElement) {
                messageElement.textContent = 'Error during login';
            }
        }
    });

    // CSRF (Vulnerable)
    addEventListenerIfExists('deleteAllCommentsForm', 'submit', async (e) => {
        e.preventDefault();
        try {
            const response = await fetch('/api/vulnerable/admin/deleteAll', {
                method: 'POST',
                // Vulnerable: No CSRF token
            });

            const data = await response.json();
            const messageElement = document.getElementById('vulnerableCsrfMessage');
            if (messageElement) {
                messageElement.textContent = response.ok ? 'All comments deleted' : 'Error deleting comments';
            }
        } catch (error) {
            const messageElement = document.getElementById('vulnerableCsrfMessage');
            if (messageElement) {
                messageElement.textContent = 'Error deleting comments';
            }
        }
    });

    // ===== SECURE IMPLEMENTATIONS =====

    // SQL Injection (Secure)
    addEventListenerIfExists('secureSearchForm', 'submit', async (e) => {
        e.preventDefault();
        const query = document.getElementById('secureSearchQuery')?.value;

        try {
            const response = await fetch(`/api/secure/search?q=${encodeURIComponent(query)}`);
            const results = await response.json();
            
            const resultsElement = document.getElementById('secureSearchResults');
            if (resultsElement) {
                resultsElement.innerHTML = results
                    .map(comment => `<div class="comment">${sanitizeHTML(comment.content)}</div>`)
                    .join('');
            }
        } catch (error) {
            const resultsElement = document.getElementById('secureSearchResults');
            if (resultsElement) {
                resultsElement.textContent = 'Error during search';
            }
        }
    });

    // XSS (Secure)
    addEventListenerIfExists('secureCommentForm', 'submit', async (e) => {
        e.preventDefault();
        const content = document.getElementById('secureCommentContent')?.value;

        try {
            const response = await fetch('/api/secure/comments', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, userId: 1 })
            });

            const data = await response.json();
            if (response.ok) {
                const commentsElement = document.getElementById('secureComments');
                if (commentsElement) {
                    commentsElement.innerHTML += 
                        `<div class="comment">${sanitizeHTML(data.content)}</div>`;
                }
                const contentElement = document.getElementById('secureCommentContent');
                if (contentElement) {
                    contentElement.value = '';
                }
            }
        } catch (error) {
            console.error('Error posting comment:', error);
        }
    });

    // Command Injection (Secure)
    addEventListenerIfExists('secureCommandForm', 'submit', async (e) => {
        e.preventDefault();
        const command = document.getElementById('secureCommand')?.value;

        try {
            const response = await fetch('/api/secure/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command })
            });

            const data = await response.json();
            const outputElement = document.getElementById('secureCommandOutput');
            if (outputElement) {
                outputElement.innerHTML = `<pre>${sanitizeHTML(data.output)}</pre>`;
            }
        } catch (error) {
            const outputElement = document.getElementById('secureCommandOutput');
            if (outputElement) {
                outputElement.textContent = 'Error executing command';
            }
        }
    });

    // Authentication (Secure)
    addEventListenerIfExists('secureLoginForm', 'submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('secureUsername')?.value;
        const password = document.getElementById('securePassword')?.value;

        try {
            const response = await fetch('/api/secure/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            const messageElement = document.getElementById('secureLoginMessage');
            if (messageElement) {
                if (response.ok) {
                    messageElement.textContent = 'Login successful!';
                } else {
                    messageElement.textContent = data.error;
                }
            }
        } catch (error) {
            const messageElement = document.getElementById('secureLoginMessage');
            if (messageElement) {
                messageElement.textContent = 'Error during login';
            }
        }
    });

    // CSRF (Secure)
    addEventListenerIfExists('deleteAllCommentsForm', 'submit', async (e) => {
        e.preventDefault();
        try {
            const csrfToken = document.cookie
                .split('; ')
                .find(row => row.startsWith('csrf-token='))
                ?.split('=')[1];

            const response = await fetch('/api/secure/admin/deleteAll', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': csrfToken
                }
            });

            const data = await response.json();
            const messageElement = document.getElementById('secureCsrfMessage');
            if (messageElement) {
                messageElement.textContent = response.ok ? 'All comments deleted' : 'Error deleting comments';
            }
        } catch (error) {
            const messageElement = document.getElementById('secureCsrfMessage');
            if (messageElement) {
                messageElement.textContent = 'Error deleting comments';
            }
        }
    });

    // SQL Injection Examples
    const sqlInjectionForm = document.getElementById('sqlInjectionForm');
    if (sqlInjectionForm) {
        sqlInjectionForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const query = document.getElementById('searchQuery').value;
            fetch(`/api/vulnerable/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => displayResult('sqlInjectionResult', data))
                .catch(error => displayResult('sqlInjectionResult', error.message, true));
        });
    }

    const sqlInjectionSecureForm = document.getElementById('sqlInjectionSecureForm');
    if (sqlInjectionSecureForm) {
        sqlInjectionSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const query = document.getElementById('searchQuerySecure').value;
            fetch(`/api/secure/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => displayResult('sqlInjectionSecureResult', data))
                .catch(error => displayResult('sqlInjectionSecureResult', error.message, true));
        });
    }

    // XSS Examples
    const xssForm = document.getElementById('xssForm');
    if (xssForm) {
        xssForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const content = document.getElementById('commentContent').value;
            fetch('/api/vulnerable/comments', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, userId: 1 })
            })
            .then(response => response.json())
            .then(data => displayResult('xssResult', data))
            .catch(error => displayResult('xssResult', error.message, true));
        });
    }

    const xssSecureForm = document.getElementById('xssSecureForm');
    if (xssSecureForm) {
        xssSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const content = document.getElementById('commentContentSecure').value;
            fetch('/api/secure/comments', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, userId: 1 })
            })
            .then(response => response.json())
            .then(data => displayResult('xssSecureResult', data))
            .catch(error => displayResult('xssSecureResult', error.message, true));
        });
    }

    // Command Injection Examples
    const commandInjectionForm = document.getElementById('commandInjectionForm');
    if (commandInjectionForm) {
        commandInjectionForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const command = document.getElementById('command').value;
            fetch('/api/vulnerable/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command })
            })
            .then(response => response.json())
            .then(data => displayResult('commandInjectionResult', data))
            .catch(error => displayResult('commandInjectionResult', error.message, true));
        });
    }

    const commandInjectionSecureForm = document.getElementById('commandInjectionSecureForm');
    if (commandInjectionSecureForm) {
        commandInjectionSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const command = document.getElementById('commandSecure').value;
            fetch('/api/secure/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command })
            })
            .then(response => response.json())
            .then(data => displayResult('commandInjectionSecureResult', data))
            .catch(error => displayResult('commandInjectionSecureResult', error.message, true));
        });
    }

    // Authentication Examples
    const authForm = document.getElementById('authForm');
    if (authForm) {
        authForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            fetch('/api/vulnerable/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => displayResult('authResult', data))
            .catch(error => displayResult('authResult', error.message, true));
        });
    }

    const authSecureForm = document.getElementById('authSecureForm');
    if (authSecureForm) {
        authSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('usernameSecure').value;
            const password = document.getElementById('passwordSecure').value;
            fetch('/api/secure/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => displayResult('authSecureResult', data))
            .catch(error => displayResult('authSecureResult', error.message, true));
        });
    }

    // CSRF Examples
    const csrfForm = document.getElementById('csrfForm');
    if (csrfForm) {
        csrfForm.addEventListener('submit', (e) => {
            e.preventDefault();
            fetch('/api/vulnerable/admin/deleteAll', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => displayResult('csrfResult', data))
            .catch(error => displayResult('csrfResult', error.message, true));
        });
    }

    const csrfSecureForm = document.getElementById('csrfSecureForm');
    if (csrfSecureForm) {
        csrfSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const token = document.getElementById('csrfToken').value;
            fetch('/api/secure/admin/deleteAll', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': token
                }
            })
            .then(response => response.json())
            .then(data => displayResult('csrfSecureResult', data))
            .catch(error => displayResult('csrfSecureResult', error.message, true));
        });
    }

    // File Upload Examples
    const fileUploadForm = document.getElementById('fileUploadForm');
    if (fileUploadForm) {
        fileUploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            
            if (!file) {
                displayResult('fileUploadResult', 'Please select a file', true);
                return;
            }

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/api/vulnerable/upload', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                displayResult('fileUploadResult', result);
            } catch (error) {
                displayResult('fileUploadResult', error.message, true);
            }
        });
    }

    const fileUploadSecureForm = document.getElementById('fileUploadSecureForm');
    if (fileUploadSecureForm) {
        fileUploadSecureForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('fileInputSecure');
            const file = fileInput.files[0];
            
            if (!file) {
                displayResult('fileUploadSecureResult', 'Please select a file', true);
                return;
            }

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/api/secure/upload', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                displayResult('fileUploadSecureResult', result);
            } catch (error) {
                displayResult('fileUploadSecureResult', error.message, true);
            }
        });
    }

    // Session Management Examples
    const sessionForm = document.getElementById('sessionForm');
    if (sessionForm) {
        sessionForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const data = document.getElementById('sessionData').value;
            fetch('/api/vulnerable/session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data })
            })
            .then(response => response.json())
            .then(data => displayResult('sessionResult', data))
            .catch(error => displayResult('sessionResult', error.message, true));
        });
    }

    const sessionSecureForm = document.getElementById('sessionSecureForm');
    if (sessionSecureForm) {
        sessionSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const data = document.getElementById('sessionDataSecure').value;
            fetch('/api/secure/session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data })
            })
            .then(response => response.json())
            .then(data => displayResult('sessionSecureResult', data))
            .catch(error => displayResult('sessionSecureResult', error.message, true));
        });
    }

    // Open Redirect Examples
    const redirectForm = document.getElementById('redirectForm');
    if (redirectForm) {
        redirectForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const url = document.getElementById('redirectUrl').value;
            window.location.href = `/api/vulnerable/redirect?url=${encodeURIComponent(url)}`;
        });
    }

    const redirectSecureForm = document.getElementById('redirectSecureForm');
    if (redirectSecureForm) {
        redirectSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const url = document.getElementById('redirectUrlSecure').value;
            window.location.href = `/api/secure/redirect?url=${encodeURIComponent(url)}`;
        });
    }

    // API Authentication Examples
    const apiAuthForm = document.getElementById('apiAuthForm');
    if (apiAuthForm) {
        apiAuthForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const apiKey = document.getElementById('apiKey').value;
            fetch('/api/vulnerable/data', {
                headers: {
                    'X-API-Key': apiKey
                }
            })
            .then(response => response.json())
            .then(data => displayResult('apiAuthResult', data))
            .catch(error => displayResult('apiAuthResult', error.message, true));
        });
    }

    const apiAuthSecureForm = document.getElementById('apiAuthSecureForm');
    if (apiAuthSecureForm) {
        apiAuthSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const apiKey = document.getElementById('apiKeySecure').value;
            fetch('/api/secure/data', {
                headers: {
                    'Authorization': `Bearer ${apiKey}`
                }
            })
            .then(response => response.json())
            .then(data => displayResult('apiAuthSecureResult', data))
            .catch(error => displayResult('apiAuthSecureResult', error.message, true));
        });
    }

    // Sensitive Data Logging Examples
    const loggingForm = document.getElementById('loggingForm');
    if (loggingForm) {
        loggingForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const data = document.getElementById('userData').value;
            fetch('/api/vulnerable/log', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data })
            })
            .then(response => response.json())
            .then(data => displayResult('loggingResult', data))
            .catch(error => displayResult('loggingResult', error.message, true));
        });
    }

    const loggingSecureForm = document.getElementById('loggingSecureForm');
    if (loggingSecureForm) {
        loggingSecureForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const data = document.getElementById('userDataSecure').value;
            fetch('/api/secure/log', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data })
            })
            .then(response => response.json())
            .then(data => displayResult('loggingSecureResult', data))
            .catch(error => displayResult('loggingSecureResult', error.message, true));
        });
    }

    // Initialize CSRF token for secure form
    fetch('/api/secure/csrf-token')
        .then(response => response.json())
        .then(data => {
            const csrfTokenInput = document.getElementById('csrfToken');
            if (csrfTokenInput) {
                csrfTokenInput.value = data.token;
            }
        })
        .catch(error => console.error('Error fetching CSRF token:', error));
});

// Helper function for XSS protection
function sanitizeHTML(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
} 