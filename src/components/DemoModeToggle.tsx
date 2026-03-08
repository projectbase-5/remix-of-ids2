
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TestTube, Database } from "lucide-react";

interface DemoModeToggleProps {
  isDemoMode: boolean;
  onToggle: (enabled: boolean) => void;
}

const DemoModeToggle = ({ isDemoMode, onToggle }: DemoModeToggleProps) => {
  return (
    <Card className="border-2 border-dashed">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {isDemoMode ? (
              <TestTube className="h-5 w-5 text-blue-500" />
            ) : (
              <Database className="h-5 w-5 text-green-500" />
            )}
            <div>
              <Label htmlFor="demo-mode" className="text-base font-medium">
                {isDemoMode ? "Demo Mode" : "Live Mode"}
              </Label>
              <p className="text-sm text-muted-foreground">
                {isDemoMode 
                  ? "Generating synthetic network events for demonstration"
                  : "Using real data sources and ingestion"
                }
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <Badge variant={isDemoMode ? "secondary" : "default"}>
              {isDemoMode ? "SIMULATION" : "REAL DATA"}
            </Badge>
            <Switch
              id="demo-mode"
              checked={isDemoMode}
              onCheckedChange={onToggle}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default DemoModeToggle;
