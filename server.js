const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

const authRoutes = require("./routes/authRoutes");
const commentRoutes = require("./routes/commentRoutes");

app.use("/api/auth", authRoutes);
app.use("/api/comments", commentRoutes);

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB Connected");
    app.listen(process.env.PORT || 5000, () => {
      console.log("Server running...");
    });
  })
  .catch((err) => console.log(err));
