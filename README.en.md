# LXD Web Manager

LXD Web Manager is a web-based management tool designed to simplify the management and operation of LXD (Linux Containers). It provides an intuitive user interface that allows users to easily manage resources such as containers, images, networks, and storage.

## Features

- Container Management: Create, start, stop, and delete containers.
- Image Management: Manage local and remote images.
- Network Management: Configure and manage container networks.
- Storage Management: Manage storage volumes and snapshots.
- User Permissions: Supports multi-user permission management.

## Installation Guide

1. Clone the repository:
   ```bash
   git clone https://gitee.com/qdmz/lxd_webmanager.git
   ```
2. Install dependencies:
   ```bash
   cd lxd_webmanager
   pip install -r requirements.txt
   ```
3. Configure the database and LXD connection information:
   - Modify the database and LXD settings in the `config.py` file.

4. Initialize the database:
   ```bash
   python manage.py db init
   python manage.py db migrate
   python manage.py db upgrade
   ```

5. Start the application:
   ```bash
   python app.py
   ```

## Usage Instructions

- Access `http://localhost:5000` to enter the web management interface.
- The default administrator username and password can be found or modified in `config.py`.

## Contribution Guidelines

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch.
3. Commit your changes.
4. Submit a Pull Request.

## License

This project is licensed under the MIT License. For details, see the [LICENSE](LICENSE) file.