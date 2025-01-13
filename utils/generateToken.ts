import jwt from "jsonwebtoken";

const generateToken = (user: any) => {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET as string, {
    expiresIn: "1d",
  });
};

export default generateToken;