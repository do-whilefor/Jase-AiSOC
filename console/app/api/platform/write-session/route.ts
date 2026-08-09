import { issueWriteSession } from "../_proxy";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  return issueWriteSession(request);
}
