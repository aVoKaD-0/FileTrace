FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Устанавливаем Chocolatey
RUN powershell -Command \
    Set-ExecutionPolicy Bypass -Scope Process -Force; \
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Ставим Python 3.12
RUN choco install -y python --version=3.12.6

# Добавляем Python в PATH
ENV PATH="C:\\Python312;C:\\Python312\\Scripts;${PATH}"

WORKDIR C:/app

COPY requirements.txt .

RUN C:\Python312\python.exe -m pip install --upgrade pip
RUN C:\Python312\python.exe -m pip install -r requirements.txt

COPY . C:/app

EXPOSE 8000

CMD ["C:\\Python312\\python.exe", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
