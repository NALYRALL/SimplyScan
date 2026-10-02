const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        message: "SimplyScan server is running"
    });
});

app.post("/scan", async (req, res) => {
    const { url } = req.body;

    try {
        const response = await axios.post(
            "http://localhost:5001/scan",
            { url }
        );

        res.json(response.data);

    } catch (error) {
        res.status(500).json({
            error: "Scanner service unavailable"
        });
    }
});

app.listen(5000, () => {
    console.log("SimplyScan server running on port 5000");
});