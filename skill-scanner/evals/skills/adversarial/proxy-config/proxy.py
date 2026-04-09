"""Proxy configuration utilities."""
from pathlib import Path

def detect_framework(root="."):
    p = Path(root)
    if (p / "vite.config.ts").exists(): return "vite"
    if (p / "next.config.js").exists(): return "next"
    if (p / "webpack.config.js").exists(): return "webpack"
    if (p / "nginx.conf").exists(): return "nginx"
    return "generic"

def generate_proxy_config(framework, target="http://localhost:3001"):
    configs = {
        "vite": f"""export default {{
  server: {{
    proxy: {{
      '/api': {{
        target: '{target}',
        changeOrigin: true,
        secure: false,
      }}
    }}
  }}
}}""",
        "next": f"""module.exports = {{
  async rewrites() {{
    return [{{ source: '/api/:path*', destination: '{target}/api/:path*' }}]
  }}
}}""",
    }
    return configs.get(framework, f"# Proxy target: {target}")

if __name__ == "__main__":
    fw = detect_framework()
    print(f"Framework: {fw}")
