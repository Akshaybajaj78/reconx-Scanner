import User from "../models/User.js";

const assignAgent = async (department) => {
  let agent = await User.findOne({
    role: "agent",
    department: department,
  });

  if (!agent) {
    agent = await User.findOne({
      role: "agent",
    });
  }

  return agent;
};

export default assignAgent;