import requests
from datetime import datetime
import json


class bark_sender():
    def __init__(self, server: str, port: int, https: bool, key: str, icon: str):
        self.url = f'{"https" if https else "http"}://{server}:{port}/{key}'
        self.icon = icon

    def bark_notify(self, title: str, text: str, data: dict, group: str, icon: str) -> int:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        content = f'{current_time}\n\n 【{text}】\n'
        for i in data:
            content += f'{i}: \t{data[i]}\n'
        data = {"body": content,
                "title": f'【{group}】 {title}',
                # "device_key": configuration['bark']['key'],
                "icon": self.icon,
                "sound": "glass.caf"}
        params = {'icon': icon,
                  "group": group}
        json_data = json.dumps(data)
        headers = {"Content-Type": "application/json; charset=utf-8"}
        try:
            response = requests.post(self.url, data=json_data, headers=headers, params=params, timeout=1)
        except Exception as e:
            print(f"Fail to send bark notification {e}")
            return 0
        return response.status_code
