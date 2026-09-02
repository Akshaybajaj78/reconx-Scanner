const triageTicket = (subject, description) => {
  const text = `${subject} ${description}`.toLowerCase();

  let department = "General";
  let urgency = "Low";
  const tags = [];

  // Department classification

  if (
    text.includes("payment") ||
    text.includes("refund") ||
    text.includes("billing") ||
    text.includes("invoice") ||
    text.includes("charged")
  ) {
    department = "Billing";
    tags.push("billing");
  }

  if (
    text.includes("password") ||
    text.includes("login") ||
    text.includes("account") ||
    text.includes("email")
  ) {
    department = "Account";
    tags.push("account");
  }

  if (
    text.includes("bug") ||
    text.includes("server") ||
    text.includes("error") ||
    text.includes("api") ||
    text.includes("website") ||
    text.includes("crash")
  ) {
    department = "Technical";
    tags.push("technical");
  }

  // Urgency detection

  if (
    text.includes("urgent") ||
    text.includes("immediately") ||
    text.includes("critical") ||
    text.includes("server down") ||
    text.includes("production down")
  ) {
    urgency = "Critical";
    tags.push("critical");
  } else if (
    text.includes("failed") ||
    text.includes("not working") ||
    text.includes("cannot access") ||
    text.includes("can't access") ||
    text.includes("payment deducted")
  ) {
    urgency = "High";
    tags.push("high-priority");
  } else if (
    text.includes("problem") ||
    text.includes("issue") ||
    text.includes("slow")
  ) {
    urgency = "Medium";
  }

  if (tags.length === 0) {
    tags.push("general");
  }

  return {
    department,
    urgency,
    tags,
  };
};

export default triageTicket;