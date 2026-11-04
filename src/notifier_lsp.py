from abc import ABC, abstractmethod

class Notifier(ABC):
    @abstractmethod
    def send(self, message: str) -> bool:
        pass

class EmailNotifier(Notifier):
    def send(self, message: str) -> bool:
        # Успешная отправка email
        return True

class SmsNotifier(Notifier):
    def send(self, message: str) -> bool:
        # Автоматическое усечение вместо выброса ValueError (сохранение контракта LSP)
        if len(message) > 160:
            message = message[:157] + "..."
        return True

class WebhookNotifier(Notifier):
    def send(self, message: str) -> bool:
        # Возвращает False вместо None при недоступности эндпоинта (сохранение типа bool)
        endpoint_reachable = False  
        if not endpoint_reachable:
            return False
        return True