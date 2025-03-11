import os
import json
import base64
import hashlib
import secrets
import string
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QLineEdit, QPushButton, QLabel,
    QMessageBox, QDialog, QFormLayout, QDialogButtonBox, QCheckBox,
    QSpinBox, QComboBox, QFileDialog, QGridLayout
)
from PySide6.QtCore import Qt, QTimer, QEvent, QSize, QRectF, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QColor, QPainter, QPixmap, QPainterPath, QRegion

class PasswordManager:
    def __init__(self, master_password):
        self.master_file = "master.key"
        self.passwords_file = "passwords.dat"
        self.categories_file = "categories.dat"
        self.salt = self._get_or_create_salt()
        self.key = self._derive_key(master_password)
        self.cipher = Fernet(self.key)
        self.base_categories = ["Соцсети", "Банки", "Работа", "Личное"]
        self.custom_categories = []
        self.load_categories()

    def export_data(self, file_path):
        """
        Экспортирует все данные в JSON файл для создания бэкапа.
        """
        try:
            data = {
                "passwords": self.load_passwords(),
                "categories": self.custom_categories,
                "metadata": {
                    "export_date": datetime.now().isoformat(),
                    "version": "1.0"
                }
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            return True
        except Exception as e:
            print(f"Ошибка при экспорте данных: {e}")
            return False

    def import_data(self, file_path):
        """
        Импортирует данные из JSON файла (бэкапа).
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Восстанавливаем пароли
            if "passwords" in data:
                self.save_passwords(data["passwords"])
            
            # Восстанавливаем категории
            if "categories" in data:
                self.custom_categories = data["categories"]
                self.save_categories()
            
            return True
        except Exception as e:
            print(f"Ошибка при импорте данных: {e}")
            return False

    def _get_or_create_salt(self):
        if not os.path.exists("salt.bin"):
            salt = os.urandom(16)
            with open("salt.bin", "wb") as f:
                f.write(salt)
        with open("salt.bin", "rb") as f:
            return f.read()

    def _derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _encrypt(self, data):
        return self.cipher.encrypt(data.encode()).decode()

    def _decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data.encode()).decode()

    def save_master_password(self, password):
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        encrypted = self._encrypt(hashed_pw)
        with open(self.master_file, "w") as f:
            f.write(encrypted)

    def verify_password(self, password):
        try:
            with open(self.master_file, "r") as f:
                stored_hash = self._decrypt(f.read())
            current_hash = hashlib.sha256(password.encode()).hexdigest()
            return stored_hash == current_hash
        except FileNotFoundError:
            return True

    def save_passwords(self, data):
        encrypted = self._encrypt(json.dumps(data))
        with open(self.passwords_file, "w") as f:
            f.write(encrypted)

    def load_passwords(self):
        try:
            with open(self.passwords_file, "r") as f:
                data = json.loads(self._decrypt(f.read()))
                for item in data.values():
                    item.setdefault("category", "Другое")
                    item.setdefault("tags", [])
                    item.setdefault("url", "")
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def load_categories(self):
        try:
            with open(self.categories_file, "r") as f:
                self.custom_categories = json.loads(self._decrypt(f.read()))
        except (FileNotFoundError, json.JSONDecodeError):
            self.custom_categories = []

    def save_categories(self):
        encrypted = self._encrypt(json.dumps(self.custom_categories))
        with open(self.categories_file, "w") as f:
            f.write(encrypted)

class PasswordItemWidget(QWidget):
    def __init__(self, service, data, main_window, parent=None):
        super().__init__(parent)
        self.service = service
        self.data = data
        self.main_window = main_window
        self.is_selected = False
        self.setup_ui()
        self.setup_animations()
        self.setProperty("is_selected", "false")

    def setup_ui(self):
        self.setFixedHeight(150)  # Фиксированная высота записи
        self.setMinimumWidth(120)  # Минимальная ширина записи
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)  # Выравнивание по центру

        # Логотип сервиса
        self.logo_label = QLabel()
        self.logo_label.setFixedSize(80, 80)  # Размер логотипа
        self.load_logo()
        layout.addWidget(self.logo_label, alignment=Qt.AlignCenter)

        # Название сервиса (жирным шрифтом)
        self.service_label = QLabel(self.service)
        self.service_label.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        self.service_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.service_label)

        # Индикатор дубликата пароля
        self.indicator = IndicatorWidget()
        self.indicator.setVisible(self.data['password'] in self.main_window.duplicate_passwords)
        layout.addWidget(self.indicator, alignment=Qt.AlignCenter)

        # Стиль для фона
        self.setStyleSheet("""
            PasswordItemWidget {
                background-color: #696969;  /* DimGray */
                border-radius: 10px;
                border: 1px solid #555;
                padding: 10px;
            }
            PasswordItemWidget:hover {
                background-color: #7a7a7a;  /* Осветление при наведении */
            }
            PasswordItemWidget[is_selected="true"] {
                background-color: #7a7a7a;
                border: 2px solid #0078d4;
            }
        """)

    def setup_animations(self):
        # Анимация нажатия
        self.click_animation = QPropertyAnimation(self, b"geometry")
        self.click_animation.setDuration(100)  # Длительность анимации
        self.click_animation.setEasingCurve(QEasingCurve.OutQuad)

    def mousePressEvent(self, event):
        # Снимаем выделение со всех элементов
        for i in range(self.main_window.grid_layout.count()):
            widget = self.main_window.grid_layout.itemAt(i).widget()
            if widget:
                widget.set_selected(False)

        # Устанавливаем выделение для текущего элемента
        self.set_selected(True)
        
        # Эффект нажатия
        self.click_animation.setStartValue(self.geometry())
        self.click_animation.setEndValue(self.geometry().adjusted(2, 2, -2, -2))
        self.click_animation.start()

        # Задержка перед открытием диалога
        QTimer.singleShot(150, lambda: self.main_window.show_password_details(self))
        super().mousePressEvent(event)

    def set_selected(self, state):
        self.is_selected = state
        self.setProperty("is_selected", "true" if state else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def mouseReleaseEvent(self, event):
        # Возврат к исходному размеру
        self.click_animation.setStartValue(self.geometry())
        self.click_animation.setEndValue(self.geometry().adjusted(-2, -2, 2, 2))
        self.click_animation.start()
        super().mouseReleaseEvent(event)

    def load_logo(self):
        """
        Загружает логотип сервиса из папки logos.
        Если логотип не найден, использует nologo.png.
        """
        try:
            if 'service' not in self.data:
                raise ValueError("Ключ 'service' отсутствует в данных")
                
            service_name = self.data['service'].lower().replace(" ", "_")
            logo_path = os.path.join("logos", f"{service_name}.png")
            
            if os.path.exists(logo_path):
                pixmap = QPixmap(logo_path)
            else:
                # Используем nologo.png, если логотип не найден
                nologo_path = os.path.join("logos", "nologo.png")
                if os.path.exists(nologo_path):
                    pixmap = QPixmap(nologo_path)
                else:
                    # Если nologo.png тоже отсутствует, используем текстовую метку
                    self.logo_label.setText("No Logo")
                    return
            
            self.logo_label.setPixmap(pixmap.scaled(
                80, 80, 
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            ))
        except Exception as e:
            print(f"Ошибка загрузки логотипа: {e}")
            self.logo_label.setText("Ошибка загрузки")

    def update_logo(self):
        """
        Обновляет логотип.
        """
        self.load_logo()

    def paintEvent(self, event):
        """
        Переопределяем метод отрисовки для закругленных углов.
        """
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        rect = QRectF(self.rect())
        path.addRoundedRect(rect, 10, 10)
        painter.setClipPath(path)
        # Исправляем цвет фона в соответствии со стилями
        painter.fillRect(self.rect(), QColor("#696969"))

class AuthDialog(QDialog):
    def __init__(self, is_new_user=False):
        super().__init__()
        self.setWindowTitle("Установка мастер-пароля" if is_new_user else "Вход")
        layout = QVBoxLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Мастер-пароль:"))
        layout.addWidget(self.password_input)
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        if is_new_user:
            layout.addWidget(QLabel("Подтвердите пароль:"))
            layout.addWidget(self.confirm_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)

class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Генератор паролей")
        
        layout = QVBoxLayout()
        
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(16)
        
        self.digits_check = QCheckBox("Цифры")
        self.digits_check.setChecked(True)
        
        self.symbols_check = QCheckBox("Спецсимволы")
        self.symbols_check.setChecked(True)
        
        self.generated_password = QLineEdit()
        
        generate_btn = QPushButton("Сгенерировать")
        generate_btn.clicked.connect(self.generate)
        
        layout.addWidget(QLabel("Длина пароля:"))
        layout.addWidget(self.length_spin)
        layout.addWidget(self.digits_check)
        layout.addWidget(self.symbols_check)
        layout.addWidget(QLabel("Сгенерированный пароль:"))
        layout.addWidget(self.generated_password)
        layout.addWidget(generate_btn)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def generate(self):
        length = self.length_spin.value()
        use_digits = self.digits_check.isChecked()
        use_symbols = self.symbols_check.isChecked()
        
        chars = string.ascii_letters
        if use_digits: chars += string.digits
        if use_symbols: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?/"
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.generated_password.setText(password)

class CategoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создать категорию")
        layout = QVBoxLayout()
        
        self.name_input = QLineEdit()
        layout.addWidget(QLabel("Название категории:"))
        layout.addWidget(self.name_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def get_category_name(self):
        return self.name_input.text().strip()

class PasswordDialog(QDialog):
    def __init__(self, parent=None, service="", login="", password="", category="", tags=[], url=""):
        super().__init__(parent)
        self.setWindowTitle("Добавить пароль" if not service else "Редактировать пароль")
        
        layout = QFormLayout()
        
        self.service = QLineEdit(service)
        self.login = QLineEdit(login)
        self.password = QLineEdit(password)
        self.password.setEchoMode(QLineEdit.Password)
        self.url_input = QLineEdit(url)
        
        self.category_combo = QComboBox()
        self.category_combo.addItems(parent.pm.base_categories + parent.pm.custom_categories)
        self.category_combo.setCurrentText(category if category else parent.pm.base_categories[0])
        
        self.tags_input = QLineEdit(", ".join(tags) if isinstance(tags, list) else tags)
        
        generate_btn = QPushButton("Сгенерировать пароль")
        generate_btn.clicked.connect(self.show_generator)
        
        layout.addRow("Сервис:", self.service)
        layout.addRow("Логин:", self.login)
        layout.addRow("Пароль:", self.password)
        layout.addRow("URL:", self.url_input)
        layout.addRow(generate_btn)
        layout.addRow("Категория:", self.category_combo)
        layout.addRow("Теги (через запятую):", self.tags_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def show_generator(self):
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec():
            self.password.setText(dialog.generated_password.text())
    
    def get_data(self):
        return {
            "service": self.service.text(),
            "login": self.login.text(),
            "password": self.password.text(),
            "category": self.category_combo.currentText(),
            "tags": [tag.strip() for tag in self.tags_input.text().split(",") if tag.strip()],
            "url": self.url_input.text()
        }

class IndicatorWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(10, 10)  # Уменьшаем размер в 2 раза
        self.color = QColor(255, 0, 0)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(self.color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, 8, 8)  # Уменьшаем размер кружка

class PasswordDetailDialog(QDialog):
    def __init__(self, data, main_window, parent=None):
        super().__init__(parent)
        self.data = data
        self.main_window = main_window  # Сохраняем ссылку на главное окно
        self.setWindowTitle("Детали записи")
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout()
        
        # Логотип сервиса
        self.logo_label = QLabel()
        self.logo_label.setFixedSize(100, 100)
        self.load_logo()
        layout.addWidget(self.logo_label, alignment=Qt.AlignCenter)
        
        # Кнопка для добавления логотипа
        self.add_logo_btn = QPushButton("Добавить логотип")
        self.add_logo_btn.clicked.connect(self.add_logo)
        layout.addWidget(self.add_logo_btn, alignment=Qt.AlignCenter)
        
        # Остальные данные
        self.service_label = QLabel(f'<a href="{data["url"]}">{data["service"]}</a>')
        self.service_label.setOpenExternalLinks(True)
        self.login_label = QLabel(f"Логин: {data['login']}")
        self.category_label = QLabel(f"Категория: {data['category']}")
        self.tags_label = QLabel(f"Теги: {', '.join(data['tags'])}")
        
        self.password_layout = QHBoxLayout()
        self.password_input = QLineEdit(data['password'])
        self.password_input.setEchoMode(QLineEdit.Password)
        self.show_password_btn = QPushButton("Показать")
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.toggled.connect(self.toggle_password)
        
        self.password_layout.addWidget(self.password_input)
        self.password_layout.addWidget(self.show_password_btn)
        
        btn_layout = QHBoxLayout()
        self.edit_btn = QPushButton("Редактировать")
        self.edit_btn.clicked.connect(self.edit_password)
        self.delete_btn = QPushButton("Удалить")
        self.delete_btn.clicked.connect(self.delete_password)
        self.close_btn = QPushButton("Закрыть")
        self.close_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addWidget(self.close_btn)
        
        layout.addWidget(self.service_label)
        layout.addWidget(self.login_label)
        layout.addWidget(self.category_label)
        layout.addWidget(self.tags_label)
        layout.addLayout(self.password_layout)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        
    def load_logo(self):
        """
        Загружает логотип сервиса из папки logos.
        """
        try:
            if 'service' not in self.data:
                raise ValueError("Ключ 'service' отсутствует в данных")
                
            service_name = self.data['service'].lower().replace(" ", "_")
            logo_path = os.path.join("logos", f"{service_name}.png")
            
            if os.path.exists(logo_path):
                pixmap = QPixmap(logo_path)
                self.logo_label.setPixmap(pixmap.scaled(
                    100, 100, 
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                ))
            else:
                self.logo_label.setText("No Logo")
        except Exception as e:
            print(f"Ошибка загрузки логотипа: {e}")
            self.logo_label.setText("Ошибка загрузки")

    def add_logo(self):
        """
        Позволяет пользователю загрузить логотип для сервиса.
        """
        try:
            from PIL import Image
        except ImportError:
            QMessageBox.warning(self, "Ошибка", "Установите библиотеку Pillow: pip install pillow")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите логотип",
            "",
            "Images (*.png *.jpg *.jpeg)"
        )
        
        if file_path:
            # Нормализуем имя сервиса для имени файла
            service_name = self.data['service'].lower().replace(" ", "_")
            logo_path = os.path.join("logos", f"{service_name}.png")
            
            os.makedirs("logos", exist_ok=True)
            
            try:
                img = Image.open(file_path)
                
                # Конвертируем в RGB если нужно
                if img.mode in ('RGBA', 'LA'):
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    background.paste(img, mask=img.split()[-1])
                    img = background
                    
                img.save(logo_path, "PNG", quality=95)
                
                # Принудительно обновляем интерфейс
                self.load_logo()
                self.main_window.update_list()
                QMessageBox.information(self, "Успех", "Логотип успешно добавлен!")
                
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Ошибка обработки изображения: {str(e)}")

    def delete_password(self):
        """
        Удаляет текущую запись.
        """
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Удалить запись для {self.data['service']}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.main_window.delete_password(self.data['service'])
            self.close()

    def toggle_password(self, checked):
        self.password_input.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        self.show_password_btn.setText("Скрыть" if checked else "Показать")
    
    def edit_password(self):
        self.main_window.edit_password(self.data)
        self.close()

class MainWindow(QMainWindow):
    def __init__(self, pm):
        super().__init__()
        self.pm = pm
        self.passwords = pm.load_passwords()
        self.setup_ui()
        self.setup_security()
        self.update_duplicates()

    def setup_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Кнопки для экспорта и импорта
        backup_layout = QHBoxLayout()
        self.export_btn = QPushButton("Экспорт данных")
        self.export_btn.clicked.connect(self.export_data)
        self.import_btn = QPushButton("Импорт данных")
        self.import_btn.clicked.connect(self.import_data)
        backup_layout.addWidget(self.export_btn)
        backup_layout.addWidget(self.import_btn)
        layout.addLayout(backup_layout)

        # Поиск и фильтр
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск по сервису, логину или тегам...")
        self.search_input.textChanged.connect(self.update_list)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("Все категории")
        self.filter_combo.addItems(self.pm.base_categories + self.pm.custom_categories)
        self.filter_combo.currentTextChanged.connect(self.update_list)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(self.search_input)
        filter_layout.addWidget(self.filter_combo)
        layout.addLayout(filter_layout)
        
        # Сетка для записей
        self.grid_widget = QWidget()
        self.grid_layout = QGridLayout(self.grid_widget)
        self.grid_layout.setSpacing(10)  # Расстояние между элементами
        self.grid_layout.setAlignment(Qt.AlignTop)  # Выравнивание по верхнему краю
        layout.addWidget(self.grid_widget)
        
        # Кнопки управления
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Добавить")
        self.add_btn.clicked.connect(self.add_password)
        self.category_btn = QPushButton("Новая категория")
        self.category_btn.clicked.connect(self.create_category)
        
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.category_btn)
        layout.addLayout(btn_layout)
        
        self.update_list()

    def export_data(self):
        """
        Экспортирует данные в выбранный файл.
        """
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт данных",
            "",
            "JSON Files (*.json)"
        )
        if file_path:
            if self.pm.export_data(file_path):
                QMessageBox.information(self, "Успех", "Данные успешно экспортированы!")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось экспортировать данные.")

    def import_data(self):
        """
        Импортирует данные из выбранного файла.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Импорт данных",
            "",
            "JSON Files (*.json)"
        )
        if file_path:
            reply = QMessageBox.question(
                self,
                "Подтверждение",
                "Вы уверены, что хотите импортировать данные? Текущие данные будут перезаписаны.",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                if self.pm.import_data(file_path):
                    self.passwords = self.pm.load_passwords()
                    self.update_list()
                    QMessageBox.information(self, "Успех", "Данные успешно импортированы!")
                else:
                    QMessageBox.warning(self, "Ошибка", "Не удалось импортировать данные.")

    def setup_security(self):
        self.inactivity_timer = QTimer()
        self.inactivity_timer.timeout.connect(self.lock)
        self.inactivity_timer.start(5 * 60 * 1000)
        self.installEventFilter(self)

    def create_list_item(self, service, data):
        """
        Создает кастомный виджет для отображения записи.
        """
        widget = PasswordItemWidget(service, data, self)  # Добавляем передачу main_window
        item = QListWidgetItem()
        item.setSizeHint(widget.sizeHint())
        item.setData(Qt.UserRole, service)
        return item, widget

    def create_list_item(self, service, data):
        """
        Создает кастомный виджет для отображения записи.
        """
        widget = PasswordItemWidget(service, data)
        item = QListWidgetItem()
        item.setSizeHint(widget.sizeHint())
        item.setData(Qt.UserRole, service)
        return item, widget

    def update_list(self):
        """
        Обновляет список записей.
        """
        self.update_duplicates()
        
        # Очищаем сетку
        for i in reversed(range(self.grid_layout.count())):
            self.grid_layout.itemAt(i).widget().setParent(None)
        
        search_text = self.search_input.text().lower()
        selected_category = self.filter_combo.currentText()
        
        row, col = 0, 0
        for service, data in self.passwords.items():
            if selected_category != "Все категории" and data["category"] != selected_category:
                continue
            
            tags = ", ".join(data["tags"])
            match = (search_text in service.lower() or
                    search_text in data["login"].lower() or
                    search_text in tags.lower())
            
            if match or not search_text:
                widget = PasswordItemWidget(service, data, self)  # Передаем self (MainWindow)
                widget.update_logo()  # Обновляем логотип
                self.grid_layout.addWidget(widget, row, col)
                col += 1
                if col >= 6:  # Максимум 6 записей в строке
                    col = 0
                    row += 1

        # Растягиваем элементы по ширине
        for i in range(6):
            self.grid_layout.setColumnStretch(i, 1)

        self.grid_widget.updateGeometry()
        self.grid_widget.update()

    def update_duplicates(self):
        password_counts = {}
        for data in self.passwords.values():
            pwd = data['password']
            password_counts[pwd] = password_counts.get(pwd, 0) + 1
        self.duplicate_passwords = [pwd for pwd, count in password_counts.items() if count > 1]

    def add_password(self):
        dialog = PasswordDialog(self)
        if dialog.exec():
            data = dialog.get_data()
            self.passwords[data['service']] = data
            self.pm.save_passwords(self.passwords)
            self.update_list()

    def delete_password(self, service):
        """
        Удаляет запись по названию сервиса.
        """
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Удалить запись для {service}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Удаляем из данных
            del self.passwords[service]
            self.pm.save_passwords(self.passwords)
            
            # Удаляем из интерфейса
            selected_widget = None
            for i in range(self.grid_layout.count()):
                widget = self.grid_layout.itemAt(i).widget()
                if widget and widget.service == service:
                    selected_widget = widget
                    self.grid_layout.removeWidget(selected_widget)
                    selected_widget.deleteLater()
                    break
            
            self.update_list()

    def show_password_details(self, widget):
        """
        Открывает диалог с деталями записи.
        """
        service = widget.service
        if service in self.passwords:
            data = self.passwords[service]
            dialog = PasswordDetailDialog(data, self)  # self передается как main_window
            dialog.exec()

    def create_category(self):
        dialog = CategoryDialog(self)
        if dialog.exec():
            category_name = dialog.get_category_name()
            if category_name and category_name not in self.pm.custom_categories:
                self.pm.custom_categories.append(category_name)
                self.pm.save_categories()
                self.update_category_filters()

    def update_category_filters(self):
        self.filter_combo.clear()
        self.filter_combo.addItem("Все категории")
        self.filter_combo.addItems(self.pm.base_categories + self.pm.custom_categories)

    def edit_password(self, old_data):
        dialog = PasswordDialog(self, **old_data)
        if dialog.exec():
            new_data = dialog.get_data()
            # Удаляем старую запись если изменилось имя сервиса
            if new_data['service'] != old_data['service']:
                del self.passwords[old_data['service']]
            self.passwords[new_data['service']] = new_data
            self.pm.save_passwords(self.passwords)
            self.update_list()

    def lock(self):
        self.close()
        auth_dialog = AuthDialog()
        if auth_dialog.exec():
            password = auth_dialog.password_input.text()
            if self.pm.verify_password(password):
                self.show()
                self.inactivity_timer.start()

    def eventFilter(self, source, event):
        if event.type() == QEvent.MouseMove or event.type() == QEvent.KeyPress:
            self.inactivity_timer.start()
        return super().eventFilter(source, event)

def main():
    app = QApplication([])
    app.setStyleSheet("""
        QMainWindow {
            background-color: #333333;  /* Темный фон приложения */
        }
    """)
    
    if not os.path.exists("master.key"):
        auth_dialog = AuthDialog(is_new_user=True)
        if auth_dialog.exec():
            password = auth_dialog.password_input.text()
            confirm = auth_dialog.confirm_input.text()
            
            if password != confirm:
                QMessageBox.critical(None, "Ошибка", "Пароли не совпадают!")
                return
                
            pm = PasswordManager(password)
            pm.save_master_password(password)
            window = MainWindow(pm)
            window.show()
            app.exec()
    else:
        auth_dialog = AuthDialog()
        if auth_dialog.exec():
            password = auth_dialog.password_input.text()
            pm = PasswordManager(password)
            if pm.verify_password(password):
                window = MainWindow(pm)
                window.show()
                app.exec()
            else:
                QMessageBox.critical(None, "Ошибка", "Неверный пароль!")

if __name__ == "__main__":
    main()