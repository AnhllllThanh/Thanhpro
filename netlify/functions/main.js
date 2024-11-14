// main.js
document.querySelector('#login-form').addEventListener('submit', function(event) {
    event.preventDefault();  // Ngăn chặn form gửi dữ liệu mặc định

    const username = document.querySelector('#username').value;
    const password = document.querySelector('#password').value;

    // Gửi yêu cầu POST đến API đăng nhập
    fetch('/login', {
        method: 'POST',  // Phương thức HTTP là POST
        headers: {
            'Content-Type': 'application/json',  // Định dạng dữ liệu là JSON
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    })
    .then(response => response.json())  // Chờ phản hồi từ server
    .then(data => {
        if (data.success) {
            // Nếu đăng nhập thành công, chuyển hướng tới trang dashboard
            window.location.href = '/dashboard';
        } else {
            // Nếu thất bại, hiển thị thông báo lỗi
            alert(data.message);
        }
    })
    .catch(error => {
        console.error('Lỗi:', error);
    });
});
