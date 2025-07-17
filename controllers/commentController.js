const Comment = require("../models/Comment");

// Create a new comment
exports.createComment = async (req, res) => {
  try {
    const { text } = req.body;
    const comment = await Comment.create({ text, user: req.userId });
    res.status(201).json(comment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Get all comments with user info
exports.getComments = async (req, res) => {
  try {
    const comments = await Comment.find().populate("user", "username");
    res.json(comments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Delete comment by id (any logged-in user)
exports.deleteComment = async (req, res) => {
  try {
    const commentId = req.params.id;
    const deleted = await Comment.findByIdAndDelete(commentId);
    if (!deleted) {
      return res.status(404).json({ message: "Comment not found" });
    }
    res.json({ message: "Comment deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Update comment by id (any logged-in user)
exports.updateComment = async (req, res) => {
  try {
    const commentId = req.params.id;
    const { text } = req.body;

    const updated = await Comment.findByIdAndUpdate(
      commentId,
      { text },
      { new: true }
    );
    if (!updated) {
      return res.status(404).json({ message: "Comment not found" });
    }
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
