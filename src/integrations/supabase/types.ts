export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "13.0.4"
  }
  public: {
    Tables: {
      adaptive_configs: {
        Row: {
          batch_size: number | null
          created_at: string
          drift_threshold: number | null
          environment_type: string
          id: string
          is_active: boolean | null
          learning_rate: number | null
          model_id: string | null
          resource_constraints: Json | null
          update_frequency: number | null
          updated_at: string
        }
        Insert: {
          batch_size?: number | null
          created_at?: string
          drift_threshold?: number | null
          environment_type: string
          id?: string
          is_active?: boolean | null
          learning_rate?: number | null
          model_id?: string | null
          resource_constraints?: Json | null
          update_frequency?: number | null
          updated_at?: string
        }
        Update: {
          batch_size?: number | null
          created_at?: string
          drift_threshold?: number | null
          environment_type?: string
          id?: string
          is_active?: boolean | null
          learning_rate?: number | null
          model_id?: string | null
          resource_constraints?: Json | null
          update_frequency?: number | null
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "adaptive_configs_model_id_fkey"
            columns: ["model_id"]
            isOneToOne: false
            referencedRelation: "ml_models"
            referencedColumns: ["id"]
          },
        ]
      }
      attack_patterns: {
        Row: {
          attack_type: string
          confidence_threshold: number | null
          countermeasures: Json | null
          created_at: string
          detection_rules: Json | null
          evasion_techniques: Json | null
          feature_signature: Json
          id: string
          pattern_name: string
          updated_at: string
        }
        Insert: {
          attack_type: string
          confidence_threshold?: number | null
          countermeasures?: Json | null
          created_at?: string
          detection_rules?: Json | null
          evasion_techniques?: Json | null
          feature_signature: Json
          id?: string
          pattern_name: string
          updated_at?: string
        }
        Update: {
          attack_type?: string
          confidence_threshold?: number | null
          countermeasures?: Json | null
          created_at?: string
          detection_rules?: Json | null
          evasion_techniques?: Json | null
          feature_signature?: Json
          id?: string
          pattern_name?: string
          updated_at?: string
        }
        Relationships: []
      }
      correlation_events: {
        Row: {
          attack_type: string
          created_at: string
          event_id: string
          event_type: string
          group_id: string
          id: string
          phase: string
          threat_score: number
          timestamp: string
        }
        Insert: {
          attack_type: string
          created_at?: string
          event_id: string
          event_type: string
          group_id: string
          id?: string
          phase: string
          threat_score?: number
          timestamp: string
        }
        Update: {
          attack_type?: string
          created_at?: string
          event_id?: string
          event_type?: string
          group_id?: string
          id?: string
          phase?: string
          threat_score?: number
          timestamp?: string
        }
        Relationships: [
          {
            foreignKeyName: "correlation_events_group_id_fkey"
            columns: ["group_id"]
            isOneToOne: false
            referencedRelation: "correlation_groups"
            referencedColumns: ["id"]
          },
        ]
      }
      correlation_groups: {
        Row: {
          composite_score: number
          created_at: string
          escalated: boolean
          first_seen: string
          id: string
          is_multi_stage: boolean
          last_seen: string
          phases: Json
          sequence_pattern: string | null
          source_ip: string
          updated_at: string
        }
        Insert: {
          composite_score?: number
          created_at?: string
          escalated?: boolean
          first_seen: string
          id?: string
          is_multi_stage?: boolean
          last_seen: string
          phases?: Json
          sequence_pattern?: string | null
          source_ip: string
          updated_at?: string
        }
        Update: {
          composite_score?: number
          created_at?: string
          escalated?: boolean
          first_seen?: string
          id?: string
          is_multi_stage?: boolean
          last_seen?: string
          phases?: Json
          sequence_pattern?: string | null
          source_ip?: string
          updated_at?: string
        }
        Relationships: []
      }
      datasets: {
        Row: {
          created_at: string
          description: string | null
          features_count: number | null
          file_path: string | null
          id: string
          name: string
          source: string
          total_records: number | null
          updated_at: string
          version: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          features_count?: number | null
          file_path?: string | null
          id?: string
          name: string
          source: string
          total_records?: number | null
          updated_at?: string
          version?: string
        }
        Update: {
          created_at?: string
          description?: string | null
          features_count?: number | null
          file_path?: string | null
          id?: string
          name?: string
          source?: string
          total_records?: number | null
          updated_at?: string
          version?: string
        }
        Relationships: []
      }
      detection_rules: {
        Row: {
          created_at: string
          cve_ids: Json | null
          description: string | null
          enabled: boolean | null
          false_positive_rate: number | null
          id: string
          last_triggered: string | null
          mitre_attack_id: string | null
          name: string
          pattern: string
          rate_limit_threshold: number | null
          rate_limit_window_seconds: number | null
          regex_pattern: string | null
          rule_type: string
          severity: string
          triggered_count: number | null
          updated_at: string
          yara_rule: string | null
        }
        Insert: {
          created_at?: string
          cve_ids?: Json | null
          description?: string | null
          enabled?: boolean | null
          false_positive_rate?: number | null
          id?: string
          last_triggered?: string | null
          mitre_attack_id?: string | null
          name: string
          pattern: string
          rate_limit_threshold?: number | null
          rate_limit_window_seconds?: number | null
          regex_pattern?: string | null
          rule_type: string
          severity?: string
          triggered_count?: number | null
          updated_at?: string
          yara_rule?: string | null
        }
        Update: {
          created_at?: string
          cve_ids?: Json | null
          description?: string | null
          enabled?: boolean | null
          false_positive_rate?: number | null
          id?: string
          last_triggered?: string | null
          mitre_attack_id?: string | null
          name?: string
          pattern?: string
          rate_limit_threshold?: number | null
          rate_limit_window_seconds?: number | null
          regex_pattern?: string | null
          rule_type?: string
          severity?: string
          triggered_count?: number | null
          updated_at?: string
          yara_rule?: string | null
        }
        Relationships: []
      }
      feature_engineering: {
        Row: {
          created_at: string
          dataset_id: string | null
          feature_selection: Json | null
          id: string
          normalization_params: Json | null
          original_features: number | null
          preprocessing_steps: Json
          processed_features: number | null
          smote_config: Json | null
        }
        Insert: {
          created_at?: string
          dataset_id?: string | null
          feature_selection?: Json | null
          id?: string
          normalization_params?: Json | null
          original_features?: number | null
          preprocessing_steps: Json
          processed_features?: number | null
          smote_config?: Json | null
        }
        Update: {
          created_at?: string
          dataset_id?: string | null
          feature_selection?: Json | null
          id?: string
          normalization_params?: Json | null
          original_features?: number | null
          preprocessing_steps?: Json
          processed_features?: number | null
          smote_config?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "feature_engineering_dataset_id_fkey"
            columns: ["dataset_id"]
            isOneToOne: false
            referencedRelation: "datasets"
            referencedColumns: ["id"]
          },
        ]
      }
      flow_metrics_log: {
        Row: {
          active_flows: number
          created_at: string
          id: string
          source_ip: string
          total_bytes: number
          total_packets: number
          unique_destinations: number
          unique_ports: number
        }
        Insert: {
          active_flows?: number
          created_at?: string
          id?: string
          source_ip: string
          total_bytes?: number
          total_packets?: number
          unique_destinations?: number
          unique_ports?: number
        }
        Update: {
          active_flows?: number
          created_at?: string
          id?: string
          source_ip?: string
          total_bytes?: number
          total_packets?: number
          unique_destinations?: number
          unique_ports?: number
        }
        Relationships: []
      }
      incident_logs: {
        Row: {
          assigned_to: string | null
          created_at: string
          destination_ip: string | null
          destination_port: number | null
          details: Json | null
          id: string
          incident_type: string
          protocol: string | null
          raw_data: Json | null
          resolution: string | null
          resolved_at: string | null
          rule_id: string | null
          severity: string
          signature_id: string | null
          source_ip: string | null
          source_port: number | null
          status: string | null
        }
        Insert: {
          assigned_to?: string | null
          created_at?: string
          destination_ip?: string | null
          destination_port?: number | null
          details?: Json | null
          id?: string
          incident_type: string
          protocol?: string | null
          raw_data?: Json | null
          resolution?: string | null
          resolved_at?: string | null
          rule_id?: string | null
          severity: string
          signature_id?: string | null
          source_ip?: string | null
          source_port?: number | null
          status?: string | null
        }
        Update: {
          assigned_to?: string | null
          created_at?: string
          destination_ip?: string | null
          destination_port?: number | null
          details?: Json | null
          id?: string
          incident_type?: string
          protocol?: string | null
          raw_data?: Json | null
          resolution?: string | null
          resolved_at?: string | null
          rule_id?: string | null
          severity?: string
          signature_id?: string | null
          source_ip?: string | null
          source_port?: number | null
          status?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "incident_logs_rule_id_fkey"
            columns: ["rule_id"]
            isOneToOne: false
            referencedRelation: "detection_rules"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "incident_logs_signature_id_fkey"
            columns: ["signature_id"]
            isOneToOne: false
            referencedRelation: "malware_signatures"
            referencedColumns: ["id"]
          },
        ]
      }
      ip_reputation: {
        Row: {
          abuse_reports: number | null
          asn: string | null
          asn_org: string | null
          country_code: string | null
          created_at: string
          first_seen: string | null
          id: string
          ip_address: string
          is_datacenter: boolean | null
          is_proxy: boolean | null
          is_tor_exit: boolean | null
          is_vpn: boolean | null
          last_checked: string | null
          last_reported: string | null
          reputation_score: number
          source: string
          threat_types: Json | null
          updated_at: string
        }
        Insert: {
          abuse_reports?: number | null
          asn?: string | null
          asn_org?: string | null
          country_code?: string | null
          created_at?: string
          first_seen?: string | null
          id?: string
          ip_address: string
          is_datacenter?: boolean | null
          is_proxy?: boolean | null
          is_tor_exit?: boolean | null
          is_vpn?: boolean | null
          last_checked?: string | null
          last_reported?: string | null
          reputation_score?: number
          source?: string
          threat_types?: Json | null
          updated_at?: string
        }
        Update: {
          abuse_reports?: number | null
          asn?: string | null
          asn_org?: string | null
          country_code?: string | null
          created_at?: string
          first_seen?: string | null
          id?: string
          ip_address?: string
          is_datacenter?: boolean | null
          is_proxy?: boolean | null
          is_tor_exit?: boolean | null
          is_vpn?: boolean | null
          last_checked?: string | null
          last_reported?: string | null
          reputation_score?: number
          source?: string
          threat_types?: Json | null
          updated_at?: string
        }
        Relationships: []
      }
      live_alerts: {
        Row: {
          alert_type: string
          created_at: string | null
          dedupe_key: string | null
          description: string
          destination_ip: string | null
          detection_module: string
          id: string
          metadata: Json | null
          severity: string
          source_ip: string
          status: string | null
        }
        Insert: {
          alert_type: string
          created_at?: string | null
          dedupe_key?: string | null
          description: string
          destination_ip?: string | null
          detection_module: string
          id?: string
          metadata?: Json | null
          severity?: string
          source_ip: string
          status?: string | null
        }
        Update: {
          alert_type?: string
          created_at?: string | null
          dedupe_key?: string | null
          description?: string
          destination_ip?: string | null
          detection_module?: string
          id?: string
          metadata?: Json | null
          severity?: string
          source_ip?: string
          status?: string | null
        }
        Relationships: []
      }
      malware_signatures: {
        Row: {
          created_at: string
          description: string | null
          detection_count: number | null
          first_seen: string | null
          hash_md5: string | null
          hash_sha1: string | null
          hash_sha256: string | null
          id: string
          ioc_indicators: Json | null
          is_active: boolean | null
          last_seen: string | null
          malware_family: string
          malware_type: string
          threat_level: string
          updated_at: string
          yara_rule: string | null
        }
        Insert: {
          created_at?: string
          description?: string | null
          detection_count?: number | null
          first_seen?: string | null
          hash_md5?: string | null
          hash_sha1?: string | null
          hash_sha256?: string | null
          id?: string
          ioc_indicators?: Json | null
          is_active?: boolean | null
          last_seen?: string | null
          malware_family: string
          malware_type: string
          threat_level?: string
          updated_at?: string
          yara_rule?: string | null
        }
        Update: {
          created_at?: string
          description?: string | null
          detection_count?: number | null
          first_seen?: string | null
          hash_md5?: string | null
          hash_sha1?: string | null
          hash_sha256?: string | null
          id?: string
          ioc_indicators?: Json | null
          is_active?: boolean | null
          last_seen?: string | null
          malware_family?: string
          malware_type?: string
          threat_level?: string
          updated_at?: string
          yara_rule?: string | null
        }
        Relationships: []
      }
      ml_models: {
        Row: {
          algorithm: string
          created_at: string
          feature_importance: Json | null
          id: string
          is_active: boolean | null
          model_artifacts: Json | null
          model_config: Json
          name: string
          status: string
          training_dataset_id: string | null
          updated_at: string
          version: string
        }
        Insert: {
          algorithm: string
          created_at?: string
          feature_importance?: Json | null
          id?: string
          is_active?: boolean | null
          model_artifacts?: Json | null
          model_config: Json
          name: string
          status?: string
          training_dataset_id?: string | null
          updated_at?: string
          version?: string
        }
        Update: {
          algorithm?: string
          created_at?: string
          feature_importance?: Json | null
          id?: string
          is_active?: boolean | null
          model_artifacts?: Json | null
          model_config?: Json
          name?: string
          status?: string
          training_dataset_id?: string | null
          updated_at?: string
          version?: string
        }
        Relationships: [
          {
            foreignKeyName: "ml_models_training_dataset_id_fkey"
            columns: ["training_dataset_id"]
            isOneToOne: false
            referencedRelation: "datasets"
            referencedColumns: ["id"]
          },
        ]
      }
      model_evaluations: {
        Row: {
          accuracy: number | null
          class_performance: Json | null
          confusion_matrix: Json | null
          created_at: string
          dataset_id: string | null
          detection_rate: number | null
          evaluation_type: string
          f1_score: number | null
          false_positive_rate: number | null
          id: string
          model_id: string | null
          precision: number | null
          recall: number | null
          roc_auc: number | null
          testing_time_ms: number | null
          training_time_ms: number | null
        }
        Insert: {
          accuracy?: number | null
          class_performance?: Json | null
          confusion_matrix?: Json | null
          created_at?: string
          dataset_id?: string | null
          detection_rate?: number | null
          evaluation_type: string
          f1_score?: number | null
          false_positive_rate?: number | null
          id?: string
          model_id?: string | null
          precision?: number | null
          recall?: number | null
          roc_auc?: number | null
          testing_time_ms?: number | null
          training_time_ms?: number | null
        }
        Update: {
          accuracy?: number | null
          class_performance?: Json | null
          confusion_matrix?: Json | null
          created_at?: string
          dataset_id?: string | null
          detection_rate?: number | null
          evaluation_type?: string
          f1_score?: number | null
          false_positive_rate?: number | null
          id?: string
          model_id?: string | null
          precision?: number | null
          recall?: number | null
          roc_auc?: number | null
          testing_time_ms?: number | null
          training_time_ms?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "model_evaluations_dataset_id_fkey"
            columns: ["dataset_id"]
            isOneToOne: false
            referencedRelation: "datasets"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "model_evaluations_model_id_fkey"
            columns: ["model_id"]
            isOneToOne: false
            referencedRelation: "ml_models"
            referencedColumns: ["id"]
          },
        ]
      }
      network_traffic: {
        Row: {
          created_at: string
          destination_ip: string
          flags: Json | null
          id: string
          is_suspicious: boolean | null
          packet_size: number | null
          payload_preview: string | null
          port: number | null
          protocol: string
          source_ip: string
        }
        Insert: {
          created_at?: string
          destination_ip: string
          flags?: Json | null
          id?: string
          is_suspicious?: boolean | null
          packet_size?: number | null
          payload_preview?: string | null
          port?: number | null
          protocol?: string
          source_ip: string
        }
        Update: {
          created_at?: string
          destination_ip?: string
          flags?: Json | null
          id?: string
          is_suspicious?: boolean | null
          packet_size?: number | null
          payload_preview?: string | null
          port?: number | null
          protocol?: string
          source_ip?: string
        }
        Relationships: []
      }
      notification_configs: {
        Row: {
          config_type: string
          created_at: string
          id: string
          is_active: boolean | null
          last_sent_at: string | null
          severity_threshold: string
          target: string
          updated_at: string
        }
        Insert: {
          config_type: string
          created_at?: string
          id?: string
          is_active?: boolean | null
          last_sent_at?: string | null
          severity_threshold?: string
          target: string
          updated_at?: string
        }
        Update: {
          config_type?: string
          created_at?: string
          id?: string
          is_active?: boolean | null
          last_sent_at?: string | null
          severity_threshold?: string
          target?: string
          updated_at?: string
        }
        Relationships: []
      }
      predictions: {
        Row: {
          actual_label: string | null
          confidence: number | null
          created_at: string
          features: Json
          feedback_provided: boolean | null
          id: string
          is_anomaly: boolean | null
          model_id: string | null
          network_event_id: string | null
          prediction: string
          prediction_time_ms: number | null
        }
        Insert: {
          actual_label?: string | null
          confidence?: number | null
          created_at?: string
          features: Json
          feedback_provided?: boolean | null
          id?: string
          is_anomaly?: boolean | null
          model_id?: string | null
          network_event_id?: string | null
          prediction: string
          prediction_time_ms?: number | null
        }
        Update: {
          actual_label?: string | null
          confidence?: number | null
          created_at?: string
          features?: Json
          feedback_provided?: boolean | null
          id?: string
          is_anomaly?: boolean | null
          model_id?: string | null
          network_event_id?: string | null
          prediction?: string
          prediction_time_ms?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "predictions_model_id_fkey"
            columns: ["model_id"]
            isOneToOne: false
            referencedRelation: "ml_models"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          avatar_url: string | null
          created_at: string
          display_name: string | null
          id: string
          updated_at: string
        }
        Insert: {
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          id: string
          updated_at?: string
        }
        Update: {
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          id?: string
          updated_at?: string
        }
        Relationships: []
      }
      response_actions: {
        Row: {
          action_type: string
          completed_at: string | null
          created_at: string
          id: string
          incident_id: string | null
          parameters: Json
          result: Json | null
          scored_incident_id: string | null
          status: string
          target_host: string | null
          target_ip: string | null
          triggered_by: string
        }
        Insert: {
          action_type: string
          completed_at?: string | null
          created_at?: string
          id?: string
          incident_id?: string | null
          parameters?: Json
          result?: Json | null
          scored_incident_id?: string | null
          status?: string
          target_host?: string | null
          target_ip?: string | null
          triggered_by?: string
        }
        Update: {
          action_type?: string
          completed_at?: string | null
          created_at?: string
          id?: string
          incident_id?: string | null
          parameters?: Json
          result?: Json | null
          scored_incident_id?: string | null
          status?: string
          target_host?: string | null
          target_ip?: string | null
          triggered_by?: string
        }
        Relationships: [
          {
            foreignKeyName: "response_actions_incident_id_fkey"
            columns: ["incident_id"]
            isOneToOne: false
            referencedRelation: "incident_logs"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "response_actions_scored_incident_id_fkey"
            columns: ["scored_incident_id"]
            isOneToOne: false
            referencedRelation: "scored_incidents"
            referencedColumns: ["id"]
          },
        ]
      }
      scored_incidents: {
        Row: {
          alert_count: number
          alert_ids: Json
          attack_types: Json
          created_at: string
          first_alert_at: string
          id: string
          last_alert_at: string
          sequence_pattern: string | null
          severity: string
          source_ip: string
          status: string
          total_score: number
          updated_at: string
        }
        Insert: {
          alert_count?: number
          alert_ids?: Json
          attack_types?: Json
          created_at?: string
          first_alert_at: string
          id?: string
          last_alert_at: string
          sequence_pattern?: string | null
          severity?: string
          source_ip: string
          status?: string
          total_score?: number
          updated_at?: string
        }
        Update: {
          alert_count?: number
          alert_ids?: Json
          attack_types?: Json
          created_at?: string
          first_alert_at?: string
          id?: string
          last_alert_at?: string
          sequence_pattern?: string | null
          severity?: string
          source_ip?: string
          status?: string
          total_score?: number
          updated_at?: string
        }
        Relationships: []
      }
      system_metrics_log: {
        Row: {
          active_connections: number | null
          cpu_usage: number
          created_at: string
          disk_usage: number
          id: string
          memory_usage: number
          network_health: number
        }
        Insert: {
          active_connections?: number | null
          cpu_usage?: number
          created_at?: string
          disk_usage?: number
          id?: string
          memory_usage?: number
          network_health?: number
        }
        Update: {
          active_connections?: number | null
          cpu_usage?: number
          created_at?: string
          disk_usage?: number
          id?: string
          memory_usage?: number
          network_health?: number
        }
        Relationships: []
      }
      threat_feeds: {
        Row: {
          api_key_required: boolean | null
          created_at: string
          entries_count: number | null
          feed_type: string
          id: string
          is_active: boolean | null
          last_updated: string | null
          name: string
          update_frequency_hours: number | null
          updated_at: string
          url: string | null
        }
        Insert: {
          api_key_required?: boolean | null
          created_at?: string
          entries_count?: number | null
          feed_type: string
          id?: string
          is_active?: boolean | null
          last_updated?: string | null
          name: string
          update_frequency_hours?: number | null
          updated_at?: string
          url?: string | null
        }
        Update: {
          api_key_required?: boolean | null
          created_at?: string
          entries_count?: number | null
          feed_type?: string
          id?: string
          is_active?: boolean | null
          last_updated?: string | null
          name?: string
          update_frequency_hours?: number | null
          updated_at?: string
          url?: string | null
        }
        Relationships: []
      }
      training_data: {
        Row: {
          attack_category: string | null
          created_at: string
          dataset_id: string | null
          features: Json
          id: string
          label: string
          processed_features: Json | null
          record_id: string
          severity: number | null
        }
        Insert: {
          attack_category?: string | null
          created_at?: string
          dataset_id?: string | null
          features: Json
          id?: string
          label: string
          processed_features?: Json | null
          record_id: string
          severity?: number | null
        }
        Update: {
          attack_category?: string | null
          created_at?: string
          dataset_id?: string | null
          features?: Json
          id?: string
          label?: string
          processed_features?: Json | null
          record_id?: string
          severity?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "training_data_dataset_id_fkey"
            columns: ["dataset_id"]
            isOneToOne: false
            referencedRelation: "datasets"
            referencedColumns: ["id"]
          },
        ]
      }
      user_roles: {
        Row: {
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "analyst" | "viewer"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "analyst", "viewer"],
    },
  },
} as const
