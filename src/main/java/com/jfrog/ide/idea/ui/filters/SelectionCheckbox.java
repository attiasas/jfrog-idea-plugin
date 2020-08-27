package com.jfrog.ide.idea.ui.filters;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.util.messages.MessageBus;
import com.jfrog.ide.idea.events.ApplicationEvents;
import org.jetbrains.annotations.NotNull;

import java.awt.event.ItemListener;
import java.util.Map;

/**
 * Created by Yahav Itzhak on 22 Nov 2017.
 */
class SelectionCheckbox<FilterType> extends MenuCheckbox {
    SelectionCheckbox(@NotNull Map<FilterType, Boolean> selectionMap, @NotNull FilterType item) {
        setText(item.toString());
        setState(selectionMap.get(item));
        addItemListener(e -> {
            selectionMap.replace(item, isSelected());
            MessageBus messageBus = ApplicationManager.getApplication().getMessageBus();
            messageBus.syncPublisher(ApplicationEvents.ON_SCAN_FILTER_CHANGE).update();
        });
    }

    void removeItemListeners() {
        for (ItemListener itemListener : getItemListeners()) {
            removeItemListener(itemListener);
        }
    }
}