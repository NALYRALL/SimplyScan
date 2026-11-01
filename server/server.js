
const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

const PORT = process.env.PORT || 5000;
const SCANNER_URL = (
    process.env.SCANNER_URL || "http://127.0.0.1:5001"
).replace(/\/$/, "");

const allowedOrigins = (
    process.env.CLIENT_URL ||
    "http://localhost:5173,https://simply-scan-gray.vercel.app"
).split(",").map(origin => origin.trim());  

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests without an Origin header (e.g. Postman).
        if (!origin || allowedOrigins.includes("*") ||
            allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error("Not allowed by CORS"));
    }
}));

app.use(express.json({ limit: "10kb" }));

// Backend health check
app.get("/", (req, res) => {
    res.json({
        message: "SimplyScan API is running",
        status: "healthy"
    });
});

// Check whether the Python scanner is reachable
app.get("/health", async (req, res) => {
    try {
        const response = await axios.get(
            `${SCANNER_URL}/health`,
            { timeout: 10000 }
        );

        res.json({
            status: "healthy",
            backend: "running",
            scanner: response.data
        });

    } catch (error) {
        res.status(503).json({
            status: "unhealthy",
            backend: "running",
            scanner: "unavailable"
        });
    }
});

// Scan endpoint
app.post("/scan", async (req, res) => {
    const { url } = req.body || {};

    if (typeof url !== "string" || !url.trim()) {
        return res.status(400).json({
            error: "A valid URL is required"
        });
    }

    try {
        const response = await axios.post(
            `${SCANNER_URL}/scan`,
            { url: url.trim() },
            {
                timeout: 120000,
                headers: {
                    "Content-Type": "application/json"
                }
            }
        );

        return res.status(response.status).json(response.data);

    } catch (error) {
        console.error(
            "SCAN REQUEST ERROR:",
            error.message
        );

        if (error.response) {
            return res.status(error.response.status).json(
                error.response.data
            );
        }

        if (error.code === "ECONNABORTED") {
            return res.status(504).json({
                error: "Scan request timed out"
            });
        }

        return res.status(502).json({
            error: "Scanner service unavailable"
        });
    }
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`SimplyScan API running on port ${PORT}`);
});
