from abc import ABC, abstractmethod
from src.sinks import AlertSink

# --- Базовый класс и реализации с соблюдением принципа LSP ---

class Notifier(ABC):
    @abstractmethod
    def send(self, message: str) -> bool:
        pass

class EmailNotifier(Notifier):
    def send(self, message: str) -> bool:
        # Успешная отправка email
        print(f"[EmailNotifier] Отправлено: {message}")
        return True

class SmsNotifier(Notifier):
    def send(self, message: str) -> bool:
        # Автоматическое усечение вместо выброса ValueError (сохранение контракта LSP)
        if len(message) > 160:
            message = message[:157] + "..."
        print(f"[SmsNotifier] Отправлено (SMS): {message}")
        return True

class WebhookNotifier(Notifier):
    def send(self, message: str) -> bool:
        # Возвращает False вместо None при недоступности эндпоинта (сохранение типа bool)
        endpoint_reachable = True  
        if not endpoint_reachable:
            print("[WebhookNotifier] Ошибка: эндпоинт недоступен")
            return False
        print(f"[WebhookNotifier] Отправлено (Webhook): {message}")
        return True

# --- Адаптер для интеграции с SIEM (реализует контракт AlertSink) ---

class NotifierLSP(AlertSink):
    """
    Нотификатор для SIEM-системы, использующий иерархию 
    с соблюдением принципа подстановки Лисков (LSP).
    """
    def __init__(self, notifiers=None):
        super().__init__()
        # Подключаем различные каналы связи
        self.notifiers = notifiers or [
            EmailNotifier(),
            SmsNotifier(),
            WebhookNotifier()
        ]

    def send(self, alert):
        # Преобразуем объект алерта в строку сообщения для нотификаторов
        message = f"[{alert.severity.value}] {alert.rule_name}: {alert.message} (Source: {alert.source})"
        
        # Рассылаем уведомления через все подключенные нотификаторы
        success_count = 0
        for notifier in self.notifiers:
            if notifier.send(message):
                success_count += 1
                
        print(f"[LSP Notifier] Успешно доставлено через {success_count}/{len(self.notifiers)} каналов.")
        return success_count > 0