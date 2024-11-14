// netlify/functions/login.js
const bcrypt = require('bcrypt');
const { User } = require("../../models/User");

exports.handler = async (event, context) => {
  if (event.httpMethod === "POST") {
    const { username, password } = JSON.parse(event.body);

    if (!username || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "Vui lòng cung cấp tên đăng nhập và mật khẩu." })
      };
    }

    try {
      const user = await User.findOne({ username });
      if (!user) {
        return {
          statusCode: 400,
          body: JSON.stringify({ message: "Tên đăng nhập không chính xác." })
        };
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return {
          statusCode: 400,
          body: JSON.stringify({ message: "Mật khẩu không đúng." })
        };
      }

      return {
        statusCode: 200,
        body: JSON.stringify({ message: "Đăng nhập thành công!" })
      };
    } catch (error) {
      return {
        statusCode: 500,
        body: JSON.stringify({ message: "Đã xảy ra lỗi khi đăng nhập." })
      };
    }
  }

  return {
    statusCode: 405,
    body: JSON.stringify({ message: "Method Not Allowed" })
  };
};
