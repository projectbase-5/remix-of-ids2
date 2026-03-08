
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Plus, Settings, Trash2, Edit } from "lucide-react";
import { DetectionRule } from "./DetectionEngine";

interface RuleManagerProps {
  rules: DetectionRule[];
  onRulesUpdate: (rules: DetectionRule[]) => void;
}

const RuleManager = ({ rules, onRulesUpdate }: RuleManagerProps) => {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [newRule, setNewRule] = useState<Partial<DetectionRule>>({
    name: "",
    type: "signature",
    severity: "medium",
    pattern: "",
    description: "",
    enabled: true,
  });

  const handleCreateRule = () => {
    if (!newRule.name || !newRule.pattern) return;

    const rule: DetectionRule = {
      id: `rule-${Date.now()}`,
      name: newRule.name,
      type: newRule.type as "signature" | "anomaly" | "behavioral",
      severity: newRule.severity as "low" | "medium" | "high",
      pattern: newRule.pattern,
      description: newRule.description || "",
      enabled: newRule.enabled || true,
      triggeredCount: 0,
    };

    onRulesUpdate([...rules, rule]);
    setNewRule({
      name: "",
      type: "signature",
      severity: "medium",
      pattern: "",
      description: "",
      enabled: true,
    });
    setIsCreateDialogOpen(false);
  };

  const handleToggleRule = (ruleId: string) => {
    onRulesUpdate(rules.map(rule => 
      rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
    ));
  };

  const handleDeleteRule = (ruleId: string) => {
    onRulesUpdate(rules.filter(rule => rule.id !== ruleId));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high": return "bg-destructive text-destructive-foreground";
      case "medium": return "bg-yellow-500 text-yellow-50";
      case "low": return "bg-green-500 text-green-50";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case "signature": return "bg-blue-500 text-blue-50";
      case "anomaly": return "bg-purple-500 text-purple-50";
      case "behavioral": return "bg-orange-500 text-orange-50";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center space-x-2">
              <Settings className="h-5 w-5" />
              <span>Detection Rules Management</span>
            </CardTitle>
            <CardDescription>Create and manage threat detection rules</CardDescription>
          </div>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button className="flex items-center space-x-2">
                <Plus className="h-4 w-4" />
                <span>Create Rule</span>
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[600px]">
              <DialogHeader>
                <DialogTitle>Create New Detection Rule</DialogTitle>
                <DialogDescription>
                  Define a new rule for detecting specific threat patterns
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="name" className="text-right">Name</Label>
                  <Input
                    id="name"
                    value={newRule.name}
                    onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                    className="col-span-3"
                    placeholder="Rule name"
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="type" className="text-right">Type</Label>
                  <Select
                    value={newRule.type}
                    onValueChange={(value) => setNewRule({ ...newRule, type: value as any })}
                  >
                    <SelectTrigger className="col-span-3">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="signature">Signature-based</SelectItem>
                      <SelectItem value="anomaly">Anomaly Detection</SelectItem>
                      <SelectItem value="behavioral">Behavioral Analysis</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="severity" className="text-right">Severity</Label>
                  <Select
                    value={newRule.severity}
                    onValueChange={(value) => setNewRule({ ...newRule, severity: value as any })}
                  >
                    <SelectTrigger className="col-span-3">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="pattern" className="text-right">Pattern</Label>
                  <Input
                    id="pattern"
                    value={newRule.pattern}
                    onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
                    className="col-span-3"
                    placeholder="Detection pattern identifier"
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="description" className="text-right">Description</Label>
                  <Textarea
                    id="description"
                    value={newRule.description}
                    onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                    className="col-span-3"
                    placeholder="Rule description"
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="enabled" className="text-right">Enabled</Label>
                  <Switch
                    id="enabled"
                    checked={newRule.enabled}
                    onCheckedChange={(checked) => setNewRule({ ...newRule, enabled: checked })}
                  />
                </div>
              </div>
              <div className="flex justify-end space-x-2">
                <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreateRule}>Create Rule</Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[500px]">
          <div className="space-y-4">
            {rules.map((rule) => (
              <div key={rule.id} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <h4 className="font-semibold">{rule.name}</h4>
                    <Badge className={getTypeColor(rule.type)}>
                      {rule.type}
                    </Badge>
                    <Badge className={getSeverityColor(rule.severity)}>
                      {rule.severity}
                    </Badge>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={rule.enabled}
                      onCheckedChange={() => handleToggleRule(rule.id)}
                    />
                    <Button size="sm" variant="outline">
                      <Edit className="h-3 w-3" />
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleDeleteRule(rule.id)}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                
                <p className="text-sm text-muted-foreground mb-2">{rule.description}</p>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                  <div>
                    <span className="font-medium">Pattern:</span> {rule.pattern}
                  </div>
                  <div>
                    <span className="font-medium">Triggered:</span> {rule.triggeredCount} times
                  </div>
                  <div>
                    <span className="font-medium">Status:</span> {rule.enabled ? "Active" : "Disabled"}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default RuleManager;
