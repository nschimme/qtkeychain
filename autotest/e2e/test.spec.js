const { test, expect } = require('@playwright/test');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8080;
const HOST = 'localhost';
const APP_PATH = path.join(__dirname, '../../build/bin/wasm-test-app.html');

let server;

test.beforeAll(async () => {
    if (!fs.existsSync(APP_PATH)) {
        throw new Error(`Test application not found at ${APP_PATH}. Make sure to build the project first.`);
    }

    server = http.createServer((req, res) => {
        const filePath = req.url === '/' ? APP_PATH : path.join(path.dirname(APP_PATH), req.url);
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end(JSON.stringify(err));
                return;
            }
            if (filePath.endsWith('.wasm')) {
                res.setHeader('Content-Type', 'application/wasm');
            }
            res.writeHead(200);
            res.end(data);
        });
    }).listen(PORT, HOST);
});

test.afterAll(() => {
    server.close();
});

test('C++ Test Application should pass', async ({ page }) => {
    const messages = [];
    page.on('console', msg => messages.push(msg.text()));

    await page.goto(`http://${HOST}:${PORT}`);

    // Wait for the "TESTS PASSED" message or a timeout
    await new Promise((resolve, reject) => {
        const interval = setInterval(() => {
            if (messages.includes('TESTS PASSED')) {
                clearInterval(interval);
                resolve();
            } else if (messages.some(m => m.includes('TESTS FAILED'))) {
                clearInterval(interval);
                reject(new Error(`Test failed with messages: ${messages.join('\\n')}`));
            }
        }, 100);

        setTimeout(() => {
            clearInterval(interval);
            reject(new Error('Test timed out.'));
        }, 10000); // 10 second timeout
    });

    // Final check to ensure no failure message appeared
    const hasFailed = messages.some(m => m.includes('TESTS FAILED'));
    expect(hasFailed).toBe(false);
});
