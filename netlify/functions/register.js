// netlify/functions/register.js
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
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return {
          statusCode: 400,
          body: JSON.stringify({ message: "Tên đăng nhập đã tồn tại." })
        };
      }

      const newUser = new User({ username, password });
      await newUser.save();

      return {
        statusCode: 200,
        body: JSON.stringify({ message: "Đăng ký thành công!" })
      };
    } catch (error) {
      return {
        statusCode: 500,
        body: JSON.stringify({ message: "Đã xảy ra lỗi khi đăng ký." })
      };
    }
  }

  return {
    statusCode: 405,
    body: JSON.stringify({ message: "Method Not Allowed" })
  };
};
