import HTTP_STATUS from '../constants';

class ApiResponse {
  statusCode: number;
  success: boolean;
  message: string;
  data: any;

  constructor(statusCode = HTTP_STATUS.OK, data = {}, message = 'Success') {
    this.statusCode = statusCode;
    this.success = statusCode < HTTP_STATUS.BAD_REQUEST;
    this.message = message;
    this.data = data;
  }

  send(res) {
    return res.status(this.statusCode).json({
      success: this.success,
      message: this.message,
      data: this.data,
    });
  }

  // Common success case (default 200)
  static success(
    res,
    data = {},
    message = 'Success',
    statusCode = HTTP_STATUS.OK,
  ) {
    return new ApiResponse(statusCode, data, message).send(res);
  }

  // For resource creation (201)
  static created(res, data = {}, message = 'Created') {
    return new ApiResponse(HTTP_STATUS.CREATED, data, message).send(res);
  }

  // For error cases
  static error(
    res,
    message = 'Something went wrong',
    statusCode = HTTP_STATUS.BAD_REQUEST,
  ) {
    return new ApiResponse(statusCode, {}, message).send(res);
  }
}

export default ApiResponse;
