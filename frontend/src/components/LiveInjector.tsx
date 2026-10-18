import { Activity } from "lucide-react";
import { Button } from "@/components/ui";

export function LiveInjector({ injecting, onToggle }: { injecting: boolean; onToggle: () => void }) {
  return (
    <div className="flex items-center gap-3 border border-white/10 bg-black/40 p-3 rounded-lg mt-4">
      <div className="text-sm font-medium text-ink-2 mr-2">Live Injection:</div>
      <Button 
        onClick={onToggle} 
        variant={injecting ? "primary" : "ghost"}
      >
        <Activity size={14} className={injecting ? "animate-pulse text-green-400" : ""} />
        {injecting ? "Stop Auto Inject" : "Start Auto Inject"}
      </Button>
    </div>
  );
}
