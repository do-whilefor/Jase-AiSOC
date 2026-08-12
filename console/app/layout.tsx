import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Jase-AiSOC | 安全运营控制台",
  description: "Jase-AiSOC 证据优先的 Linux 安全事件、资产、恶意文件与响应审批控制台。",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
