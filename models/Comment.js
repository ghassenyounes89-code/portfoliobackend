import mongoose from "mongoose";

const commentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  text: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  approved: {  // <-- ADD THIS FIELD
    type: Boolean,
    default: false
  }
});

export default mongoose.model("Comment", commentSchema);