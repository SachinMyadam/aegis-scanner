const express = require('express');
const bodyParser = require('body-parser');
const puppeteer = require('puppeteer');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());

app.post('/scan', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ status: "error", error: "No URL provided" });
    }

    console.log(`[Sandbox] Starting scan for: ${url}`);
    let browser;
    let sandboxReport = {
        status: "error",
        screenshot_base64: null,
        dom_hash: null,
        malicious_scripts_detected: false,
        error: "Unknown error",
    };

    try {
        // Launch Puppeteer using the system installed Chromium
        browser = await puppeteer.launch({
            executablePath: '/usr/bin/chromium',
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage", // Critical for Docker stability
                "--disable-gpu",
                "--no-zygote",
                "--single-process" 
            ]
        });

        const page = await browser.newPage();
        await page.setViewport({ width: 1280, height: 800 });

        // Block fonts/images to speed up
        await page.setRequestInterception(true);
        page.on("request", (request) => {
            const resourceType = request.resourceType();
            if (["image", "media", "font"].includes(resourceType)) {
                request.abort();
            } else {
                request.continue();
            }
        });

        const response = await page.goto(url, { waitUntil: "networkidle2", timeout: 30000 });

        if (response && response.status() >= 400) {
            throw new Error(`HTTP Error Status: ${response.status()}`);
        }

        const screenshotBuffer = await page.screenshot({ encoding: "base64" });
        const htmlContent = await page.content();

        const maliciousScripts =
            htmlContent.includes("eval(function(p,a,c,k,i,r)") ||
            htmlContent.includes(".localstorage") ||
            htmlContent.includes("document.cookie");

        const domHash = crypto.createHash("sha256").update(htmlContent).digest("hex");

        sandboxReport = {
            status: "ok",
            screenshot_base64: screenshotBuffer,
            dom_hash: domHash,
            malicious_scripts_detected: maliciousScripts,
            error: null,
        };

    } catch (error) {
        sandboxReport.error = error.message;
        console.error(`[Sandbox Error] ${error.message}`);
    } finally {
        if (browser) await browser.close();
    }

    res.json(sandboxReport);
});

app.listen(PORT, () => {
    console.log(`Sandbox Microservice listening on port ${PORT}`);
});
