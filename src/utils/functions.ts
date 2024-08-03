export const generateRandomString = () => {
  return Math.random().toString(36).slice(2, 12);
};

export const extractToken = (req: any) => {
  if (
    req.headers.authorization &&
    req.headers.authorization.split(" ")[0] === "Bearer"
  ) {
    return req.headers.authorization.split(" ")[1];
  } else if (req.query && req.query.token) {
    return req.query.token;
  }
  return null;
};

export const checkPrivileged = (
  givenPrivileges: string[],
  tokenPrivileges: string[]
) => {
  for (let privilege of givenPrivileges) {
    const found = tokenPrivileges.find((p: string) => p == privilege);
    if (found) return true;
  }
  return false;
};
