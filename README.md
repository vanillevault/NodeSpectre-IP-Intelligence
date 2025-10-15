# NodeSpectre IP Intelligence — Vanille Systems v1.3

> «Control, stealth & digital supremacy»  
> Autonomous underground OSINT module for IP tracing, ASN analysis, and VPN/Proxy detection.



## 🛰 Overview

NodeSpectre IP Intelligence es un módulo táctico de **Vanille Systems** diseñado para:

- Rastrear IPs públicas o internas.
- Consultar información geográfica, ISP y ASN.
- Detectar automáticamente **VPN, proxies y hosting/cloud**.
- Analizar heurísticas de ISP/ASN para identificar proveedores sospechosos.
- Generar logs y reportes exportables.
- Compatible con APIs externas opcionales para mayor precisión.

Todo en un entorno **bash**, minimalista y seguro.
---

## ⚙️ Requisitos

- `bash` ≥ 4
- `curl`
- `jq`
- Opcional: clave API de proveedores VPN/Proxy (`VPN_API_PROVIDER` + `VPN_API_KEY`).



## 📦 Instalación

1. Clona o copia el script `vanille_ipintel.sh` a tu nodo:

```bash
mkdir -p ~/.config/nodespectre
cp vanille_ipintel.sh ~/.config/nodespectre/
chmod +x ~/.config/nodespectre/vanille_ipintel.sh

2. Asegúrate de tener jq y curl instalados:



sudo apt update && sudo apt install jq curl -y

3. (Opcional) Configura proveedor externo para detección más precisa:



export VPN_API_PROVIDER="vpnapi"  # o ipqs
export VPN_API_KEY="TU_API_KEY"




🚀 Uso

Ejecuta el módulo:

~/.config/nodespectre/vanille_ipintel.sh

Menú interactivo:

1. My IP — rastrea tu propia IP pública.


2. Track IP — ingresa cualquier IP para rastrear.


3. Export report — genera un reporte .txt de la IP especificada.


4. Exit — salir del módulo.






📝 Funcionalidades

✅ Rastreo de IP con geolocalización, ISP y coordenadas.

✅ ASN Lookup: nombre, país, descripción, prefijos, peers y RIR.

✅ Heurística automática para detectar VPN, proxies y hosting/cloud.

✅ Proveedor externo opcional (vpnapi.io o IPQualityScore) para mayor precisión.

✅ Export de reportes en ~/.config/nodespectre/logs/.

✅ Logs diarios con timestamp y detalles del análisis.

🔒 Diseño seguro, solo lectura/consulta, no modifica la red ni ataca hosts.





📂 Directorio de logs

Los logs y reportes se guardan en:

~/.config/nodespectre/logs/

Formato: iptrace_YYYY-MM-DD.log o export_IP_HH-MM-SS.txt.


---

⚡ Heurística de detección

Combina señales de hosting flag, privacy API, bogon IP, y palabras clave de ISP/ASN.

Consolida un score 0–100 que indica el riesgo:

0–20 → clean

21–49 → maybe-hosting

50–79 → suspicious (possible VPN/Proxy/Host)

80–100 → hosting/vpn (very likely)






🔒 Seguridad y privacidad

No requiere root.

No modifica la red ni el sistema.

Compatible con entornos OSINT bajo Tor/ZeroTier/Tailscale.

API keys opcionales, pueden ser configuradas como variables de entorno.





💡 Recomendaciones

Para detección de alta confianza, activa un proveedor externo.

Útil para análisis OSINT, rastreo de amenazas y auditorías de seguridad.

Compatible con integración a NodeSpectre Panel o scripts automáticos.





🖤 Autor

Vanille
