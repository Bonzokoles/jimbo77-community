import * as React from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { TurnstileWidget } from '@/components/turnstile';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useConfig } from '@/hooks/use-config';
import { getSecurityHeaders } from '@/lib/api';
import { getUser } from '@/lib/auth';
import { attachFancybox, highlightCodeBlocks, renderMarkdownToHtml } from '@/lib/markdown';
import { validateText } from '@/lib/validators';

interface PostEditorProps {
  categories: any[];
  onCreatePost: (title:
  const { config } = useConfig();
  const [createOpen
      .catch(() => {});
  }, [newContent, previewOpen]);

  // UPLOAD OBRAZKA
  async function uploadImage(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    setUploadError('');
    if (file.size
