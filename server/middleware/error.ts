import { NextFunction, Request, Response } from "express";
import ErrorHandler from "../utils/ErrorHandler";

export const ErrorMiddleware = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  err.statusCode = err.statusCode || 500;
  err.message = err.message || "Internal Server Error";

  // wrong mongodb id error
  if (err.name === "CastError") {
    const message = `Resource not found with id of ${err.value}`;
    err = new ErrorHandler(message, 400);
  }

  // duplicate key error
  if (err.code === 11000) {
    const value = Object.values(err.keyValue)[0];
    const key = Object.keys(err.keyValue)[0];
    const message = `Duplicate field value ${value} for field ${key} `;
    err = new ErrorHandler(message, 400);
  }

  // wrong jwt token error
  if (err.name === "JsonWebTokenError") {
    const message = "Invalid token, please login again";
    err = new ErrorHandler(message, 401);
  }

  // jwt expired error
  if (err.name === "TokenExpiredError") {
    const message = "Token expired, please login again";
    err = new ErrorHandler(message, 401);
  }

  res.status(err.statusCode).json({
    success: false,
    error: err.message,
  });
};
