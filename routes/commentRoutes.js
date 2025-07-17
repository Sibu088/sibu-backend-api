const express = require("express");
const router = express.Router();
const { 
  createComment, 
  getComments, 
  deleteComment, 
  updateComment 
} = require("../controllers/commentController");
const auth = require("../middleware/authMiddleware");

router.get("/", getComments);
router.post("/", auth, createComment);
router.delete("/:id", auth, deleteComment);
router.put("/:id", auth, updateComment);

module.exports = router;
