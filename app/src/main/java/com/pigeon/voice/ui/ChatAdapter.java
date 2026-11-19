package com.pigeon.voice.ui;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.LruCache;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.pigeon.voice.R;
import com.pigeon.voice.net.ChatMessage;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * RecyclerView Adapter for rendering encrypted text messages, chunked shared images,
 * and cryptographic security events in the call timeline.
 */
public final class ChatAdapter extends RecyclerView.Adapter<ChatAdapter.ChatViewHolder> {

    public interface OnImageClickListener {
        void onImageClicked(ChatMessage imageMessage, Bitmap decodedBitmap);
    }

    private final List<ChatMessage> messages = new ArrayList<>();
    private final LruCache<String, Bitmap> bitmapCache = new LruCache<>(24);
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss", Locale.US);
    private final OnImageClickListener imageClickListener;

    public ChatAdapter(OnImageClickListener imageClickListener) {
        this.imageClickListener = imageClickListener;
    }

    public void setMessages(List<ChatMessage> initialList) {
        messages.clear();
        if (initialList != null) {
            messages.addAll(initialList);
        }
        notifyDataSetChanged();
    }

    public void addOrUpdateMessage(ChatMessage msg) {
        if (msg == null) {
            return;
        }
        for (int i = 0; i < messages.size(); i++) {
            if (messages.get(i).getMessageId().equals(msg.getMessageId())) {
                messages.set(i, msg);
                notifyItemChanged(i);
                return;
            }
        }
        messages.add(msg);
        notifyItemInserted(messages.size() - 1);
    }

    @NonNull
    @Override
    public ChatViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_chat_message, parent, false);
        return new ChatViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ChatViewHolder holder, int position) {
        ChatMessage msg = messages.get(position);
        if (msg.getType() == ChatMessage.Type.SYSTEM) {
            holder.tvSystemMessage.setVisibility(View.VISIBLE);
            holder.layoutChatBubble.setVisibility(View.GONE);
            holder.tvSystemMessage.setText(msg.getText());
            return;
        }

        holder.tvSystemMessage.setVisibility(View.GONE);
        holder.layoutChatBubble.setVisibility(View.VISIBLE);

        FrameLayout.LayoutParams params =
                (FrameLayout.LayoutParams) holder.layoutChatBubble.getLayoutParams();
        if (msg.isOutgoing()) {
            params.gravity = Gravity.END;
            holder.layoutChatBubble.setBackgroundResource(R.drawable.bg_bubble_outgoing);
            holder.tvSenderName.setText("You");
        } else {
            params.gravity = Gravity.START;
            holder.layoutChatBubble.setBackgroundResource(R.drawable.bg_bubble_incoming);
            holder.tvSenderName.setText(msg.getSenderName());
        }
        holder.layoutChatBubble.setLayoutParams(params);

        if (msg.getType() == ChatMessage.Type.IMAGE && msg.getImageBytes() != null) {
            holder.ivSharedImage.setVisibility(View.VISIBLE);
            Bitmap bmp = bitmapCache.get(msg.getMessageId());
            if (bmp == null) {
                byte[] bytes = msg.getImageBytes();
                bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
                if (bmp != null) {
                    bitmapCache.put(msg.getMessageId(), bmp);
                }
            }
            final Bitmap finalBmp = bmp;
            holder.ivSharedImage.setImageBitmap(finalBmp);
            holder.ivSharedImage.setOnClickListener(v -> {
                if (imageClickListener != null && finalBmp != null) {
                    imageClickListener.onImageClicked(msg, finalBmp);
                }
            });
            holder.tvMessageText.setText(msg.getText());
        } else {
            holder.ivSharedImage.setVisibility(View.GONE);
            holder.ivSharedImage.setOnClickListener(null);
            holder.tvMessageText.setText(msg.getText());
        }

        String timeStr = timeFormat.format(new Date(msg.getTimestampEpochMs()));
        String statusStr;
        if (msg.isOutgoing()) {
            if (msg.isDelivered()) {
                statusStr = " • ✓ E2EE Delivered";
            } else if (msg.getTransferProgress() < 100) {
                statusStr = " • Encrypting " + msg.getTransferProgress() + "%";
            } else {
                statusStr = " • Sent";
            }
        } else {
            statusStr = " • Verified E2EE";
        }
        holder.tvMessageMeta.setText(timeStr + statusStr);
    }

    @Override
    public int getItemCount() {
        return messages.size();
    }

    static final class ChatViewHolder extends RecyclerView.ViewHolder {
        final TextView tvSystemMessage;
        final LinearLayout layoutChatBubble;
        final TextView tvSenderName;
        final ImageView ivSharedImage;
        final TextView tvMessageText;
        final TextView tvMessageMeta;

        ChatViewHolder(@NonNull View itemView) {
            super(itemView);
            tvSystemMessage = itemView.findViewById(R.id.tvSystemMessage);
            layoutChatBubble = itemView.findViewById(R.id.layoutChatBubble);
            tvSenderName = itemView.findViewById(R.id.tvSenderName);
            ivSharedImage = itemView.findViewById(R.id.ivSharedImage);
            tvMessageText = itemView.findViewById(R.id.tvMessageText);
            tvMessageMeta = itemView.findViewById(R.id.tvMessageMeta);
        }
    }
}
